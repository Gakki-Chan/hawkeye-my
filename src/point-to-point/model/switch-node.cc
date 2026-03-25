#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>
#include <sys/file.h>
#include "ns3/log.h"
namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	m_lastSignalEpoch = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
	
	//RDMA NPA init
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < epochNum; j++)
			for (uint32_t k = 0; k < flowEntryNum; k++)
				m_flowTelemetryData[i][j][k] = FlowTelemetryData();
	for (uint32_t j = 0; j < epochNum; j++)
		for (uint32_t k = 0; k < pCnt; k++)
			m_portTelemetryData[j][k] = PortTelemetryData();
			// 端口级的遥测数据主要判断端口在某个时间片中是否发生拥塞、排队的包数、经过的包总数
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++){
			m_portToPortBytes[i][j] = 0; // 统计端口到端口之间是否有流量经过
			for(uint32_t k = 0; k < portToPortSlot; k++)
				m_portToPortBytesSlot[i][j][k] = 0; // 分时间片来记录端口之间的流量关系
		}
	for (uint32_t i = 0; i < pCnt; i++) {
		m_lastPollingEpoch[i] = 0;
		m_lastEventID[i] = 0;
		m_portSawPfcSinceLastSignal[i] = 0;
	}
	m_slotIdx = 0;
	m_nodeWeight.resize(50); // 节点权重初始化
	for(uint32_t i=0; i < 50; i++)
		m_nodeWeight[i] = 0;
	for (uint32_t i = 0; i < flowEntryNum; i++) // 流权重初始化
		m_flowWeight[i] = 0;

}
void SwitchNode::NotifyPfcEvent(uint32_t ifIndex, uint32_t qIndex, bool isPause) {
    if (isPause) {
        m_portSawPfcSinceLastSignal[ifIndex]++;
    }
}

std::string uint32_to_ipv4(uint32_t ip){
    	// 分解四个字节
    	uint8_t b1 = (ip >> 24) & 0xFF;
    	uint8_t b2 = (ip >> 16) & 0xFF;
    	uint8_t b3 = (ip >> 8)  & 0xFF;
    	uint8_t b4 =  ip        & 0xFF;
    	// 格式化为字符串
    	char buffer[16];
    	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", b1, b2, b3, b4);
    	return std::string(buffer);
} // 32 bit 变成点分十进制，更容易看
int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){// GetOutDev的作用是找到这个包的出口端口
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);
	else if (ch.l3Prot == 0xFA)
		buf.u32[2] = ch.polling.sport | ((uint32_t)ch.polling.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){ // 就是看入口端口的总排队量是否达到 pfc 阈值
		device->SendPfc(qIndex, 0); // 发送 pfc
		m_mmu->SetPause(inDev, qIndex); // 将入口端口设为pause状态，表示它已经将上游发送端口暂停
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}
void SwitchNode::WriteFlowEntry(uint32_t idx,uint32_t epoch,uint32_t flowid){ // idx means outport
	if(fp_flowdata == NULL)
		return;
	if(m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcIp == 0)
		return;
	m_flowTelemetryData[idx][epoch][flowid].durationSeconds = Simulator::Now().GetSeconds() - m_flowTelemetryData[idx][epoch][flowid].startTimeSeconds;
	/**/
	std::string sip = uint32_to_ipv4(m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcIp);	
	//fprintf(fp_flowdata, "%d,", flowid);
	fprintf(fp_flowdata, "%s,", sip.c_str());
	//fprintf(fp_flowdata, "%s,", dip.c_str());
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcPort);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.dstPort);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.protocol);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].minSeq);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].maxSeq);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].ackCount);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].nackCount);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].packetFwdNum);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].totalFwdBytes);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].totalBwdBytes);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].enqQdepth);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].pfcPausedPacketNum);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowWeight);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].nodeWeight);
	//fprintf(fp_flowdata, "%f,", m_flowTelemetryData[idx][epoch][flowid].startTimeSeconds);
	fprintf(fp_flowdata, "%f\n", m_flowTelemetryData[idx][epoch][flowid].durationSeconds);
	
}//add 添加写flowdata函数

void SwitchNode::OutputTelemetry(uint32_t port, uint32_t inport, bool isSignal){
	if(fp_telemetry == NULL)
		return;
	int fd_out = fileno(fp_telemetry);
	flock(fd_out, LOCK_EX);
	int epoch = GetEpochIdx();
	double timeInSeconds = Simulator::Now().GetSeconds();
	// fprintf(fp_telemetry,"epoch now\n\n");
	if(isSignal){
		fprintf(fp_telemetry,"\n\nsignal\nepoch %d nowTime %fs\n", epoch, timeInSeconds);
		fprintf(fp_telemetry,"\n\nsignal\ntraffic meter form port %d to port %d\n", inport, port);
		fprintf(fp_telemetry, "portToPortBytes\n");
		fprintf(fp_telemetry, "%d\n\n", m_portToPortBytes[inport][port]);
		fprintf(fp_telemetry,"\n\nsignal\nport telemetry data for port %d\n", port);
		fprintf(fp_telemetry, "enqQdepth pfcPausedPacketNum\n");
		fprintf(fp_telemetry, "%d ", m_portTelemetryData[epoch][port].enqQdepth);
		fprintf(fp_telemetry, "%d ", m_portTelemetryData[epoch][port].pfcPausedPacketNum);
		// fprintf(fp_telemetry, "%d\n\n", m_portTelemetryData[epoch][port].packetNum);//保留packetNum
		fprintf(fp_telemetry,"\n\nsignal\nflow telemetry data for port %d\n", port);
	}	
	else{
		fprintf(fp_telemetry,"\n\npolling\nepoch %d nowTime %fs\n", epoch, timeInSeconds);
		fprintf(fp_telemetry,"\n\npolling\nflow telemetry data for port %d\n", port);
	}
		
	// fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol minSeq maxSeq packetNum enqQdepth pfcPausedPacketNum\n");
	fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol packetFwdNum totalFwdBytes enqQdepth pfcPausedPacketNum\n");
				
	if (true) for(int i = 0; i < flowEntryNum; i++){
		if(m_flowTelemetryData[port][epoch][i].flowTuple.srcIp != 0 && Simulator::Now().GetTimeStep() - m_flowTelemetryData[port][epoch][i].lastTimeStep <= epochTime * (epochNum - 1)){
			fprintf(fp_telemetry, "%d ", i);
			fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[port][epoch][i].flowTuple.srcIp);
			fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[port][epoch][i].flowTuple.dstIp);
			fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].flowTuple.srcPort);
			fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].flowTuple.dstPort);
			fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].flowTuple.protocol);
			// fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].minSeq);
			// fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].maxSeq);//add 先兼容一下吧
			fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].packetFwdNum);//add
			fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].totalFwdBytes);//add
			// fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].packetNum);
			// fprintf(fp_telemetry, "%d ", m_flowTelemetryData[port][epoch][i].enqQdepth);
			fprintf(fp_telemetry, "%d ",m_flowTelemetryData[port][epoch][i].enqQdepth );
			fprintf(fp_telemetry, "%d\n", m_flowTelemetryData[port][epoch][i].pfcPausedPacketNum);
			// fprintf(fp_telemetry, "%d\n", m_flowTelemetryData[port][epoch][i].pfcPausedPacketNum);
			m_flowTelemetryData[port][epoch][i].flowWeight = m_flowWeight[i];
			uint32_t tmpnid = (m_flowTelemetryData[port][epoch][i].flowTuple.srcIp >> 8) & 0xffff;
			m_flowTelemetryData[port][epoch][i].nodeWeight = m_nodeWeight[tmpnid];
			WriteFlowEntry(port,epoch,i);
		}
		
	}
	fprintf(fp_telemetry, "0 0 0 0 0 0 0 0 0 0\n");
	fprintf(fp_telemetry,"\n");
	flock(fd_out, LOCK_UN);
	fflush(fp_telemetry);
}
bool SwitchNode::ShouldTriggerSignal(uint32_t port){
	if (m_portSawPfcSinceLastSignal[port] > 0 || m_portTelemetryData[GetEpochIdx()][port].pfcPausedPacketNum > 0)
		return true;
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[port]);
	if (device == nullptr)
		return false;
	for (uint32_t qIndex = 1; qIndex < qCnt; qIndex++){
		if (device->GetEgressPaused(qIndex))
			return true;
	}
	return false;
}
void SwitchNode::ClearPfcEvent(uint32_t ifIndex) {
    m_portSawPfcSinceLastSignal[ifIndex] = 0;
}
int SwitchNode::GetOutDevToAnalysis(){
	auto entry = m_rtTable.find(m_analysis_addr.Get());
	
	if (entry == m_rtTable.end())		// 在路由表中，此目的ip没有对应的下一跳出口vector
		return -1;

	auto &nexthops = entry->second;

	return nexthops[0];
}//发送给 analysis 的设备
void SwitchNode::SendSignalToAnalysis(uint32_t event_id){
	int idx = GetOutDevToAnalysis(); //获取egress dev
	// Create and Send p to analysis server
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[idx]);
	device->SendAnalysis(event_id, m_analysis_addr);
}//add 发送给分析服务器
void SwitchNode::UpdateFlowWeight(){//读取文件中的flowid src_ip, flow_weight来更新权重
	FILE* fin = fopen("mix/find_root_cal.txt","r");
	if(fin == NULL) return;
	if(flock(fileno(fin),LOCK_SH|LOCK_NB)== -1){
		perror("flock");
	}
	uint64_t ftime;
	uint32_t flow_id,src_ip,src_id,flow_weight;
	int temp_node_weight[50];
	for(uint32_t i=0; i<50; i++)
		temp_node_weight[i]=0;
	fscanf(fin, "%lu\n", &ftime);
	if(ftime != m_lastUpdateWeight){
		m_lastUpdateWeight = ftime;
		for (uint32_t i = 0; i < flowEntryNum; i++)
			m_flowWeight[i] = 0;
		for (uint32_t i = 0; i < m_nodeWeight.size(); i++)
			m_nodeWeight[i] = 0;

		while(fscanf(fin,"%u %u %u\n",&flow_id, &src_ip, &flow_weight) != EOF){

			if(flow_id >= flowEntryNum)
				continue;

			m_flowWeight[flow_id] = flow_weight;
			src_id = (src_ip >> 8) & 0xffff;
			if(src_id < 50)
				temp_node_weight[src_id] += flow_weight;
		
			}
		for(uint32_t i=0; i < 50; i++){
			m_nodeWeight[i] = temp_node_weight[i];
		}
	}

	flock(fileno(fin), LOCK_UN);
	fclose(fin);
	return;
}
void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	//RDMA NPA : signal packet parse
	if (ch.l3Prot == 0xFB){
		// NS_LOG_UNCOND("Normal signal receive");
		if(ch.signal.congestionPort != 0){
			// NS_LOG_UNCOND("host send sig");
			UpdateFlowWeight();
			return;
		}
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		uint32_t event_id = ch.signal.eventID;
		for (uint32_t idx = 0; idx < pCnt; idx++){
			if(m_portToPortBytes[inDev][idx] > 0){
				bool shouldTrigger = ShouldTriggerSignal(idx);
				OutputTelemetry(idx, inDev, true);
				// NS_LOG_UNCOND("0xFB branch enter");
				// NS_LOG_UNCOND("node=" << GetId()
    			// 	<< " l3=0xFB"
    			// 	<< " inDev=" << inDev
    			// 	<< " idx=" << idx
    			// 	<< " should=" << shouldTrigger
    			// 	<< " exportPfc=" << m_portExportPfcPausedPacketNum[idx]
    			// 	<< " paused3=" << DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(3)
    			// 	<< " lastEvent=" << m_lastEventID[idx]
    			// 	<< " event=" << event_id);


				if(shouldTrigger){
					
					if(event_id > m_lastEventID[idx] + 500000 || m_lastEventID[idx] == 0){
						m_lastEventID[idx] = event_id;
					}else{
						continue;
					}
					// NS_LOG_UNCOND("signal fasong ---oxFB");

					DynamicCast<QbbNetDevice>(m_devices[idx])-> SendSignal(event_id);
				}
				// NS_LOG_UNCOND("signal fasong analy");
				SendSignalToAnalysis(event_id);
				ClearPfcEvent(idx);
			}
		}
		return;	
	}
	//RDMA NPA : polling packet parse 
	else if(ch.l3Prot == 0xFA){
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		int idx = GetOutDev(p, ch);
		UpdateFlowWeight();
		uint32_t event_id = ch.polling.eventID;
		bool inShouldTrigger = ShouldTriggerSignal(inDev);
		bool outShouldTrigger = ShouldTriggerSignal(idx);
// 		NS_LOG_UNCOND("0xFA branch enter");
// 		NS_LOG_UNCOND("node=" << GetId()
//     		<< " l3=0xFA"
//     		<< " inDev=" << inDev
//     		<< " idx=" << idx
//     		<< " should=" << outShouldTrigger
//     		<< " exportPfc=" << m_portExportPfcPausedPacketNum[idx]
//     		<< " paused3=" << DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(3)
//     		<< " lastEvent=" << m_lastEventID[idx]
//     		<< " event=" << event_id);


		if(inShouldTrigger || outShouldTrigger){
			if(event_id > m_lastEventID[idx] + 500000 || m_lastEventID[idx] == 0){
				m_lastEventID[idx] = event_id;

				// NS_LOG_UNCOND("signal fasong -----oxFA");
				DynamicCast<QbbNetDevice>(m_devices[idx])-> SendSignal(event_id);
			}
		}
		OutputTelemetry(idx, inDev, false);
		// NS_LOG_UNCOND("signal fasong analy");
		SendSignalToAnalysis(event_id);
		ClearPfcEvent(idx);
	}

	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFA || ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());
				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}

		// RDMA NPA
		if(qIndex != 0){
			if((Simulator::Now().GetTimeStep() / (epochTime / portToPortSlot)) % portToPortSlot != m_slotIdx){
				m_slotIdx = (Simulator::Now().GetTimeStep() / (epochTime / portToPortSlot)) % portToPortSlot;
				for(uint32_t inDev = 0; inDev < pCnt; inDev++){
					for(uint32_t outDev = 0; outDev < pCnt; outDev++){
						m_portToPortBytes[inDev][outDev] -= m_portToPortBytesSlot[inDev][outDev][m_slotIdx];
						m_portToPortBytesSlot[inDev][outDev][m_slotIdx] = 0;
					}
				}
			}
			m_portToPortBytesSlot[inDev][idx][m_slotIdx] += p->GetSize();
			m_portToPortBytes[inDev][idx] += p->GetSize(); 
			int origin_flow_idx = idx;
			// ack如果走普通PG的话，应该把ack映射成发包的流才行
			FiveTuple fiveTuple;
			if(ch.l3Prot == 0xFC || ch.l3Prot == 0xFD){
				CustomHeader origin_flow_ch;
				origin_flow_ch.sip = ch.dip;
				origin_flow_ch.dip = ch.sip;
				origin_flow_ch.l3Prot = 0x11; //udp
				origin_flow_ch.udp.sport = ch.udp.dport;
				origin_flow_ch.udp.dport = ch.udp.sport;
				origin_flow_idx = GetOutDev(p,origin_flow_ch);
				fiveTuple.srcIp = origin_flow_ch.sip;
				fiveTuple.dstIp = origin_flow_ch.dip;
				fiveTuple.srcPort = origin_flow_ch.udp.sport;
				fiveTuple.dstPort = origin_flow_ch.udp.dport;
				fiveTuple.protocol = (uint8_t)origin_flow_ch.l3Prot;
			}else{
				fiveTuple.srcIp = ch.sip;
				fiveTuple.dstIp = ch.dip;
				fiveTuple.srcPort = ch.l3Prot == 0x06 ? ch.tcp.sport : ch.udp.sport,
				fiveTuple.dstPort = ch.l3Prot == 0x06 ? ch.tcp.dport : ch.udp.dport,
				fiveTuple.protocol = (uint8_t)ch.l3Prot;
			}
			bool paused = DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(qIndex);
			uint32_t qdepth = m_mmu->ingress_queue_length[inDev][qIndex] - 1;

			uint32_t epochIdx = GetEpochIdx();
			uint32_t flowIdx = FiveTupleHash(fiveTuple);
			auto &entry = m_flowTelemetryData[origin_flow_idx][epochIdx][flowIdx];//ack映射为一个flow add
			bool newEntry = Simulator::Now().GetTimeStep() - entry.lastTimeStep > epochTime * (epochNum - 1);
			if (entry.flowTuple == fiveTuple && !newEntry){
				uint32_t seq = ch.l3Prot == 0x06 ? ch.tcp.seq : ch.udp.seq;
				if(seq < entry.minSeq){
					entry.minSeq = seq;
				}
				if(seq > entry.maxSeq){
					entry.maxSeq = seq;
				}

				if(ch.l3Prot == 0xFC){ 
					entry.ackCount++;
					entry.totalBwdBytes += p->GetSize();
				}
				else if(ch.l3Prot == 0xFD){ 
					entry.nackCount++;
					entry.totalBwdBytes += p->GetSize();
				} else{
					entry.packetFwdNum++; 
					entry.totalFwdBytes += p->GetSize();
				}//add 记录 totalFwdBytes即流实际发送的数据字节数 totalBwdBytes流返回的ack nack字节数，可能有用

				entry.packetNum++; //总包数，留着
				entry.enqQdepth += qdepth;
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = ((fiveTuple.srcIp >> 8) & 0xffff) < m_nodeWeight.size() ? m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff] : 0;
				if(paused){
					entry.pfcPausedPacketNum++;
				 }
				entry.lastTimeStep = Simulator::Now().GetTimeStep();
			} else{
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = ((fiveTuple.srcIp >> 8) & 0xffff) < m_nodeWeight.size() ? m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff] : 0;
				entry.endTimeSeconds = Simulator::Now().GetSeconds();
				WriteFlowEntry(origin_flow_idx,epochIdx,flowIdx);//记录流表条目


				entry.flowTuple = fiveTuple;
				entry.minSeq = entry.maxSeq = ch.l3Prot == 0x06 ? ch.tcp.seq : ch.udp.seq;
				entry.ackCount = entry.nackCount = 0;
				entry.packetFwdNum = 0;
				entry.totalFwdBytes = entry.totalBwdBytes = 0;
				if(ch.l3Prot == 0xFC){ 
					entry.ackCount = 1;
					entry.totalBwdBytes = p->GetSize();
				}
				else if(ch.l3Prot == 0xFD){ 
					entry.nackCount = 1;
					entry.totalBwdBytes = p->GetSize();
				}else{ 
					entry.packetFwdNum = 1;
					entry.totalFwdBytes = p->GetSize();
				}
				entry.enqQdepth = qdepth;
				entry.pfcPausedPacketNum = 0;
				if(paused){ // if is pause
					entry.pfcPausedPacketNum++;
				}
				entry.packetNum = 1;
				entry.lastTimeStep = Simulator::Now().GetTimeStep();
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = ((fiveTuple.srcIp >> 8) & 0xffff) < m_nodeWeight.size() ? m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff] : 0;
				entry.startTimeSeconds = Simulator::Now().GetSeconds();
				entry.endTimeSeconds = 0;
			}
			auto &portEntry = m_portTelemetryData[epochIdx][idx];
			bool newPortEntry = Simulator::Now().GetTimeStep() - portEntry.lastTimeStep > epochTime * (epochNum - 1);
			if (!newPortEntry){
				portEntry.enqQdepth += qdepth;
				portEntry.packetNum++;
				if(paused){
					portEntry.pfcPausedPacketNum++;
				}
				portEntry.lastTimeStep = Simulator::Now().GetTimeStep();
			} else{
				portEntry.enqQdepth = m_mmu->ingress_queue_length[inDev][qIndex] - 1;
				portEntry.pfcPausedPacketNum = 0;
				portEntry.packetNum = 1;
				if (paused) {
    				portEntry.pfcPausedPacketNum++;
				}
				portEntry.lastTimeStep = Simulator::Now().GetTimeStep();
			}
		}

		m_bytes[inDev][idx][qIndex] += p->GetSize();
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

uint32_t SwitchNode::FiveTupleHash(const FiveTuple &fiveTuple){
	return EcmpHash((const uint8_t*)&fiveTuple, sizeof(fiveTuple), flowHashSeed) % flowEntryNum;
}

uint32_t SwitchNode::GetEpochIdx(){
	return Simulator::Now().GetTimeStep() / epochTime % epochNum;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	// NS_LOG_UNCOND("++++++node receive ++++++");
	SendToDev(packet, ch);
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		if (m_ecnEnabled){
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
			if (egressCongested){
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);
				p->RemoveHeader(h);
				h.SetEcn((Ipv4Header::EcnType)0x03);
				p->AddHeader(h);
				p->AddHeader(ppp);
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);
	}
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3){ // HPCC
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
			}else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								)/fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] = p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

} /* namespace ns3 */
