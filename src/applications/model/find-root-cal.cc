#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>	// uint32_t
#include <iostream>
#include <fstream>
#include <vector>
#include <dirent.h>
#include <string.h>
#include <cstring>
#include <sys/file.h>
#include <algorithm>
#include "ns3/simulator.h"

#include "find-root-cal.h"


namespace ns3{

FindRootCal::FindRootCal(){
	flowContNum = 0;
}

FindRootCal::~FindRootCal(){
	fclose(fout);
	vexList.clear();
	lastPos.clear();
}

void FindRootCal::PrintNodeFlow(){
    	if(hasAddPortToFlow){
    		hasAddPortToFlow = false;
    		
    		fout = fopen(fout_path.c_str(), "w");
    		flock(fileno(fout), LOCK_EX);
    	
    		fprintf(fout, "%ld\n",Simulator::Now().GetTimeStep());
    		int size = vexList.size();
    		for(int i = 0; i < size; i++)
        		if(vexList[i].nodeIdx == -1) fprintf(fout, "%d %d %d\n", vexList[i].portIdx, vexList[i].tag, vexList[i].flowWeight);
        
        	flock(fileno(fout), LOCK_UN);
        	fclose(fout);
		fflush(fout);
		
		ClearWeight();
		
		if(PRINT_EN) printf("\nHas fprintf all node result in mix/find_root_cal.txt\n");
	
	}//将所有的流节点打印到find_root_cal中
    	return;
}

void FindRootCal::ClearWeight(){
	vexList.clear();
}//销毁vexList

void FindRootCal::SetNextHop(std::map< Ptr<Node>, std::map< Ptr<Node>, std::vector<Ptr<Node>> > > *nexth){
	nexthop = nexth;
}//传路由表


int FindRootCal::GetVertexIdx(int nodeid, int portid){
    //找Node 
    int i = 0;
    for(std::vector<VertexNode>::iterator it = vexList.begin(); it != vexList.end(); it++){
        if(it->nodeIdx == nodeid && it->portIdx == portid) 
            return i;        
        i++;
    }//找节点在vexList中的位置
    // 若没有Node，就新建一个 
    VertexNode v;
    v.nodeIdx = nodeid; v.portIdx = portid; v.tag = 0;
    vexList.push_back(v);
    
    return i;
}

int FindRootCal::GetEdge(int srcvex, int dstvex){
     // 找边 
    int i = 0;
    for(std::vector<EdgeNode>::iterator it = vexList[srcvex].edges.begin(); it != vexList[srcvex].edges.end(); it++){
        if(it->dstVex == dstvex) 
            return i;
        i++;
    }//找srcvex所有边，看有没有通向dstvex的
    // 没有边，于是新建一个边 
    EdgeNode e;
    e.dstVex = dstvex;
    vexList[srcvex].edges.push_back(e);

    
    return i;//返回边的id
}
//使用节点id+端口来锁定vertex
int FindRootCal::GetEdge(int srcnode, int srcport, int dstnode, int dstport){
    // 找端点 
    int src = GetVertexIdx(srcnode, srcport); 
    int dst = GetVertexIdx(dstnode, dstport);
     // 找边 
    int i = 0;
    for(auto it = vexList[src].edges.begin(); it != vexList[src].edges.end(); it++){
        if(it->dstVex == dst) 
            return i;
        i++;
    }
    // 没有边，于是新建一个边 
    EdgeNode e;
    e.dstVex = dst;
    vexList[src].edges.push_back(e);

    return i;
}

void FindRootCal::AddFlow(int srcvex, int dstvex, int flownum){
    	int edge = GetEdge(srcvex, dstvex);
    
	vexList[srcvex].edges[edge].flowNum += flownum;//源节点到目的节点的边的流数目变大
    	vexList[dstvex].flowWeight += flownum;//目的节点流权重+flownum
    	vexList[srcvex].flowWeight -= flownum;
    	
    	if(PRINT_EN)
    		printf("AddFlow: %d.%d to %d.%d %d\n", 
    		vexList[srcvex].nodeIdx, vexList[srcvex].portIdx, vexList[dstvex].nodeIdx, vexList[dstvex].portIdx, flownum);
}

void FindRootCal::AddFlow(int srcnode, int srcport, uint32_t srcip, int dstnode, int dstport, int flownum){
    if(flownum == 0)
        return;

    int edge = GetEdge(srcnode, srcport, dstnode, dstport);
    int src = GetVertexIdx(srcnode, srcport);
    int dst =  GetVertexIdx(dstnode, dstport);
    
    vexList[src].edges[edge].flowNum += flownum;//流被端口暂停了多少包
    vexList[dst].flowWeight += flownum;
    vexList[src].flowWeight -= flownum;
    
    if(srcnode == -1){
    	vexList[src].tag = srcip;
    }else if(dstnode == -1){
    	vexList[dst].tag = srcip;
    }
    
    if(PRINT_EN)
    	printf("AddFlow: %d.%d to %d.%d %d\n", srcnode, srcport, dstnode, dstport, flownum);
}

void FindRootCal::AddFlowInNode(int vexIdx){
	
	int num = vexList[vexIdx].nextnode.size();
	
    	if(PRINT_EN)
		printf("Add flow from Vertex %d.%d to next node: %d pause flow can be add.\n",
			 		vexList[vexIdx].nodeIdx, vexList[vexIdx].portIdx, num);
	if(num == 0) return;
	
	for(int i = 0; i < num; i++){ //遍历端口节点vexIdx中等待的所有流
		// 找到流i要流向的下一个节点next
	    	int next = 0;
	    	int size = vexList.size();
	    	int nextnode = vexList[vexIdx].nextnode[i];
	    	for(next = 0; next < size; next++)
			if(vexList[next].nodeIdx == nextnode) break;
			
		if(next == size) // 如果流i的下一个节点next不在（说明还没收到next的遥测数据）
			continue;
		
		// 如果找到了流i的下一个节点next: vexList[vexIdx] ---pfcPauseNum---> vexList[next]
		AddFlow(vexIdx, next, vexList[vexIdx].pfcPauseNum[i]);
		vexList[vexIdx].nextnode[i] = -1;
		vexList[vexIdx].pfcPauseNum[i] = -1;
		
	}
	
	auto it1 = std::remove(vexList[vexIdx].nextnode.begin(), vexList[vexIdx].nextnode.end(), -1);
	vexList[vexIdx].nextnode.erase(it1, vexList[vexIdx].nextnode.end());
	auto it2 = std::remove(vexList[vexIdx].pfcPauseNum.begin(), vexList[vexIdx].pfcPauseNum.end(), -1);
	vexList[vexIdx].pfcPauseNum.erase(it2, vexList[vexIdx].pfcPauseNum.end());
	
	return;
}

void FindRootCal::ReadAllFiles(std::vector<std::string> fileNames){
	int size = fileNames.size();
	if(PRINT_EN) {
		printf("Read %d files List as follow:\n", size);
		for(int i = 0; i < size; i++)
			printf("%s\n", fileNames[i].c_str());
	}
	
	// 算出所有 flow to Port + 流争用
	for(int i = 0; i < size; i++){ 
		ReadFileForPause(fileNames[i]);	
	}
	
	// 算出所有 Node to nextNode
	if(PRINT_EN) printf("\n");
	size = vexList.size();
	for(int i = 0; i < size; i++){
		if(vexList[i].nodeIdx == -1) continue;
		AddFlowInNode(i);
	}
	
	// 结果写入find_root_cal.txt文件
	PrintNodeFlow();
}


void FindRootCal::ReadOneFile(uint32_t node){
	
	// 算出所有 flow to currNode + 流争用
	std::string filename = "mix/telemetry_" + std::to_string(node) + ".txt";
	ReadFileForPause(filename);
	
	// 算出所有 Node to nextNode
	int size = vexList.size();
	for(int i = 0; i < size; i++){
		if(vexList[i].nodeIdx == -1) continue;
		AddFlowInNode(i);
	}
	// 结果写入find_root_cal.txt文件
	PrintNodeFlow();
	
	return;
}

void FindRootCal::ReadFileForPause(std::string &filename){
	
	uint32_t node;
	char* line;
	size_t len = 0;
		
	node=0;
	for(int i = 14; filename[i] != '.'; i++){
		node = (node * 10) + filename[i] - '0';
	}
		
	fin = fopen(filename.c_str(), "r");
	if(flock(fileno(fin), LOCK_SH | LOCK_NB) == -1){// 加共享锁
		perror("flock to read error");
        	fclose(fin); 
        	return;
	}
	
	 if(lastPos.find(node) != lastPos.end()) // 找到上次读到的位置
	 	fseek(fin, lastPos[node], SEEK_SET);
	 
	
	ssize_t ret = getline(&line, &len, fin);
	hasAddFlowToPort = false, hasAddPortToFlow = false;
	while(ret != -1){
		if(strcmp(line, "polling\n") == 0)
			ReadPolling(node);
		else if(strcmp(line, "signal\n") == 0){
			//bool ok=false;
			//if(hasAddPortToFlow) ok=true, hasAddPortToFlow=false;
			ReadSignal(node);
			//if(ok) hasAddPortToFlow=true;
			
		}
		lastPos[node] = ftell(fin);//记录本次读取的位置
		
		ret = getline(&line, &len, fin);
	}
		
	flock(fileno(fin), LOCK_UN);
	fclose(fin);
	
	free(line);
	
	return;
}

int FindRootCal::GetNextHop(uint32_t node, uint32_t dstnode){
	auto i = nexthop->begin();//通过调用setnexthop将路由表传递给nexthop
	while(i->first->GetId() != node){//找到node的路由表
		i++;
	};
	auto table = i->second;
	auto j = table.begin();
	while(j->first->GetId() != dstnode){
		j++;
	};//找到node->dstnode的路由表
	int nodeid = j->second[0]->GetId();//找到对应id
	if(j->second[0]->GetNodeType() == 0)//下一跳是host
		nodeid = -1;
	return nodeid;
}

void FindRootCal::ReadPolling(uint32_t node){
	
	int ret;
	uint32_t port;
	uint32_t flowIdx,srcIp, dstIp, sport, dport, proto, packetNum, bytes, enqQdepth, pfcPausedPacketNum;
	char* line = NULL;
	size_t len = 0;
	
	do{
		ret = getline(&line, &len, fin);
	}while(strcmp(line, "polling\n"));
	// 读取流信息
	ret = fscanf(fin, "flow telemetry data for port %u\n", &port);
	bool canAdd=true;
	if(hasAddFlowToPort) canAdd=false;
	ret = getline(&line, &len, fin);
	while(true){
		ret = fscanf(fin, "%u %08x %08x %u %u %u %u %u %u %u\n", &flowIdx, &srcIp, &dstIp, &sport, &dport, &proto, &packetNum, &bytes, &enqQdepth, &pfcPausedPacketNum);
		if(dstIp == 0) break;
		if(pfcPausedPacketNum > 0){
			if(canAdd){
				uint32_t dstnode = (dstIp >> 8) & 0xffff;
				int nextnode = GetNextHop(node, dstnode);
				AddFlow(-1, flowIdx, srcIp, node, port, pfcPausedPacketNum);
				vexList[GetVertexIdx(node, port)].pfcPauseNum.push_back(pfcPausedPacketNum);
				vexList[GetVertexIdx(node, port)].nextnode.push_back(nextnode);
				hasAddFlowToPort = true;
			}		
		}
	}
	
	free(line);
	
	return;
}
    	
void FindRootCal::ReadSignal(uint32_t node){
	
	uint32_t port, size, iport, oport;
	uint32_t flowIdx, srcIp, dstIp, sport, dport, proto, packetNum, bytes, enqQdepth, pfcPausedPacketNum;
	char* line = NULL;
	size_t len = 0;
	int ret;
	
	size = 1;
	do{
		ret = getline(&line, &len, fin);
		if(strcmp(line,"signal\n") == 0) size--;
	}while(size > 0);
	ret = fscanf(fin, "traffic meter form port %u to port %u\n", &iport, &oport);
	size = 2;
	do{
		ret = getline(&line, &len, fin);
		if(strcmp(line, "signal\n") == 0) size--;
	}while(size > 0);
	
	// 读取流信息
	bool canAdd=true, canAddCont=true;
	if(hasAddFlowToPort) canAdd=false;
	if(hasAddPortToFlow) canAddCont=false;
	if(PRINT_EN) 
	    printf("hasAddPortToFlow=%d, canAddCont=%d\n", hasAddPortToFlow, canAddCont);
	ret = fscanf(fin, "flow telemetry data for port %u\n", &port);
	ret = getline(&line, &len, fin);
	while(true){
		ret = fscanf(fin, "%u %08x %08x %u %u %u %u %u %u %u\n", &flowIdx, &srcIp, &dstIp, &sport, &dport, &proto, &packetNum, &bytes, &enqQdepth, &pfcPausedPacketNum);
		if(dstIp == 0) break;
		if(pfcPausedPacketNum > 0){
			if(canAdd){
				uint32_t dstnode = (dstIp >> 8) & 0xffff;
				int nextnode = GetNextHop(node, dstnode);
				AddFlow(-1, flowIdx, srcIp, node, port, pfcPausedPacketNum);
				vexList[GetVertexIdx(node, port)].pfcPauseNum.push_back(pfcPausedPacketNum);
				vexList[GetVertexIdx(node, port)].nextnode.push_back(nextnode);
				hasAddFlowToPort = true;
			}		
		}else{
			if(canAddCont){
				uint32_t dstnode = (dstIp >> 8) & 0xffff;
				int nextnode = GetNextHop(node, dstnode);
				if(nextnode == -1){
					AddFlow(node, iport, srcIp, -1, flowIdx, packetNum);
					hasAddPortToFlow = true;
				}
			}
		}
	}
	free(line);
	
	return;
}

};
