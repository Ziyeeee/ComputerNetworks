#include "router.h"
#include <stdint.h>
#include <stdlib.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

struct ListNode
{
  /* data */
  RoutingTableEntry *node;
  ListNode *nextNode;
};

ListNode *Head = NULL;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  ListNode *nowNode, *prNode, *newNode;
  RoutingTableEntry *newEntry;
  nowNode = Head;
  prNode = NULL;
  if (insert == true)
  {
    while (nowNode != NULL)
    {
      if (entry.len < nowNode->node->len)
      {
        prNode = nowNode;
        nowNode = nowNode->nextNode;
      }
      else if (entry.len == nowNode->node->len)
      {
        if (entry.addr < nowNode->node->addr)
        {
          prNode = nowNode;
          nowNode = nowNode->nextNode;
        }
        else if (entry.addr > nowNode->node->addr)
        {
          newNode = (ListNode*)malloc(sizeof(ListNode));

          newEntry = (RoutingTableEntry*)malloc(sizeof(RoutingTableEntry));
          newEntry->addr = entry.addr;
          newEntry->len = entry.len;
          newEntry->if_index = entry.if_index;
          newEntry->nexthop = entry.nexthop;

          newNode->node = newEntry;
          prNode->nextNode = newNode;
          newNode->nextNode = nowNode;
          return;
        }
        else    //entry.addr == nowNode->node->addr
        {
          nowNode->node->if_index = entry.if_index;
          nowNode->node->nexthop = entry.nexthop;
          return;
        }
      }
      else  //entry.len > nowNode->node->len
      {
        newNode = (ListNode*)malloc(sizeof(ListNode));

        newEntry = (RoutingTableEntry*)malloc(sizeof(RoutingTableEntry));
        newEntry->addr = entry.addr;
        newEntry->len = entry.len;
        newEntry->if_index = entry.if_index;
        newEntry->nexthop = entry.nexthop;

        newNode->node = newEntry;
        if(prNode == NULL)
        {
          newNode->nextNode = Head;
          Head = newNode;
        }
        else
        {
          prNode->nextNode = newNode;
          newNode->nextNode = nowNode;
        }
        return;
      }
    }
    if (prNode == NULL)
    {
      Head = (ListNode*)malloc(sizeof(ListNode));

      newEntry = (RoutingTableEntry*)malloc(sizeof(RoutingTableEntry));
      newEntry->addr = entry.addr;
      newEntry->len = entry.len;
      newEntry->if_index = entry.if_index;
      newEntry->nexthop = entry.nexthop;

      Head->node = newEntry;
      Head->nextNode = NULL;
    }
    else    //prNode != NULL
    {
      newNode = (ListNode*)malloc(sizeof(ListNode));

      newEntry = (RoutingTableEntry*)malloc(sizeof(RoutingTableEntry));
      newEntry->addr = entry.addr;
      newEntry->len = entry.len;
      newEntry->if_index = entry.if_index;
      newEntry->nexthop = entry.nexthop;

      newNode->node = newEntry;
      prNode->nextNode = newNode;
      newNode->nextNode = NULL;
    }
  }
  else  //insert == false
  {
    while (nowNode != NULL)
    {
      if (entry.len < nowNode->node->len)
      {
        prNode = nowNode;
        nowNode = nowNode->nextNode;
      }
      else if (entry.len == nowNode->node->len)
      {
        if (entry.addr < nowNode->node->addr)
        {
          prNode = nowNode;
          nowNode = nowNode->nextNode;
        }
        else if (entry.addr == nowNode->node->addr)
        {
          prNode->nextNode = nowNode->nextNode;
          free(nowNode->node);
          free(nowNode);
          break;
        }
        else    //entry.addr > nowNode->node->addr
        {
          return;
        }
      }
      else
      {
        return;
      }
    }
  }
  return;
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  ListNode *nowNode;
  nowNode = Head;
  *nexthop = 0;
  *if_index = 0;
  while (nowNode != NULL)
  {
    if (addr < nowNode->node->addr)
    {
      nowNode = nowNode->nextNode;
    }
    else if (addr == nowNode->node->addr)
    {
      *nexthop = nowNode->node->nexthop;
      *if_index = nowNode->node->if_index;
      return true;
    }
    else
    {
      return false;
    }
  }
  return false;
}
