#ifndef CALROOT_H // 确保头文件内容只被编译一次
#define CALROOT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>	// uint32_t
#include <fstream>
#include <vector>
#include <map>
#include <string.h>
#include <ns3/ptr.h>
#include <ns3/node.h>


namespace ns3{

struct EdgeNode {// 边表结点
        int dstVex;         // 表示该边的终点
        int flowNum;
        EdgeNode(){
            flowNum=0; 
        }
};

struct VertexNode {// 顶点  
        int nodeIdx, portIdx, tag; // nodeIdx=-1代表此节点代表某个流，而非某Node，此时portIdx就是流Idx
        int flowWeight;
        std::vector<int> pfcPauseNum, nextnode;
        std::vector<EdgeNode> edges; // 记录从这个点出发的所有边 
        VertexNode(){
            flowWeight = 0; 
        } 
};   

class FindRootCal : public Object{   // 可以识别根本原因（例如流争用）、PFC传播路径和受害流。 
public:
	bool PRINT_EN = false;	// =true时，执行这个class时打印信息到屏幕上
	std::string fout_path;
	FILE *fin, *fout;
	
    	FindRootCal();
    	~FindRootCal();
    	void SetNextHop(std::map< Ptr<Node>, std::map< Ptr<Node>, std::vector<Ptr<Node>> > > *nexth);
    	void ReadAllFiles(std::vector<std::string> fileNames); 	// read all file and refresh the topo in txt
    	void ReadOneFile(uint32_t node);			// read one file and refresh the topo in txt
    
private:
	int rootNodeIdx;
	int flowContNum;
    	std::vector<VertexNode> vexList; //记录所有节点信息（包含流和交换机、host节点
    	std::map<Ptr<Node>, std::map<Ptr<Node>, std::vector<Ptr<Node>>> > *nexthop;
    	std::map<int, long> lastPos; // 文件上一次读取位置
    	bool hasAddFlowToPort, hasAddPortToFlow;
    	
    	void PrintNodeFlow();
    	int GetVertexIdx(int nodeid, int portid);
    	int GetEdge(int srcvex, int dstvex);
    	int GetEdge(int srcnode, int srcport, int dstnode, int dstport);
    	int GetNextHop(uint32_t node, uint32_t dstnode);
    	void AddFlowInNode(int vexIdx);
    	void AddFlow(int srcvex, int dstvex, int flownum);
    	void AddFlow(int srcnode, int srcport, uint32_t srcip, int dstnode, int dstport, int flownum);
    	void ReadPolling(uint32_t node);
    	void ReadSignal(uint32_t node);
    	void ReadFileForPause(std::string &filename);
    	void ClearWeight();
};

};

#endif
