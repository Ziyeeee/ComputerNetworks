#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  uint8_t *p;
  uint32_t mask;
  int headLen, nowLen, totalLen;
  int flag, num = 0;

  p = (uint8_t*)(packet + 2);
  totalLen = uint16_t(p[0]<<8) + uint16_t(p[1]);
  if (totalLen <= len)  //IP总长度
  {
    headLen = (packet[0] & 0x0f) * 4;
    p = (uint8_t*)(packet) + headLen + 8;
    if ((p[0] == 0x01 || p[0] == 0x02) && (p[1] == 0x02) && (p[2] == 0x00) && (p[3] == 0x00))
    {
      nowLen = headLen + 8 + 4;
      p += 4;
      while (nowLen < totalLen)
      {
        flag = 0;
        if (((packet[headLen + 8] == 0x01 && p[0] == 0x00 && p[1] == 0x00) || (packet[headLen + 8] == 0x02 && p[0] == 0x00 && p[1] == 0x02))
            && (p[2] == 0x00) && (p[3] == 0x00)
            && ((p[16] == 0x00 && p[17] == 0x00 && p[18] == 0x00 && p[19] != 0x00) || (p[16] == 0x00 && p[17] == 0x00 && p[18] == 0x01 && p[19] == 0x00)))
        {
          output->command = uint8_t(packet[headLen + 8]);
          mask = uint32_t(p[8]<<24) + uint32_t(p[9]<<16) + uint32_t(p[10]<<8) + uint32_t(p[11]);
          while ((flag < 2) && (mask != 0))
          {
            if ((mask & 0x00000001) == flag)
            {
              mask = mask >> 1;
            }
            else
            {
              flag++;
            }
          }
          if (flag >= 2)
          {
            return false;
          }
          else
          {
            output->numEntries = num + 1;
            output->entries[num].addr = uint32_t(p[4]<<24) + uint32_t(p[5]<<16) + uint32_t(p[6]<<8) + uint32_t(p[7]);
            output->entries[num].mask = uint32_t(p[8]<<24) + uint32_t(p[9]<<16) + uint32_t(p[10]<<8) + uint32_t(p[11]);
            output->entries[num].nexthop = uint32_t(p[12]<<24) + uint32_t(p[13]<<16) + uint32_t(p[14]<<8) + uint32_t(p[15]);
            output->entries[num].metric = uint32_t(p[16]<<24) + uint32_t(p[17]<<16) + uint32_t(p[18]<<8) + uint32_t(p[19]);
          }
        }
        else
        {
          return false;
        }
      }
      return true;
    }
  }
  return false;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  int length = 0;
  int num = 0;
  uint8_t *p;
  if (rip->numEntries > 0)
  {
    buffer[0] = uint8_t(rip->command);
    buffer[1] = uint8_t(0x02);
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    length = 4 + 20 * rip->numEntries;

    p = buffer + 4;
    for (num = 0; num < rip->numEntries; num++)
    {
      p[0] = 0x00;
      p[1] = 0x02;
      p[2] = 0x00;
      p[3] = 0x00;

      p[4] = uint8_t((rip->entries[num].addr & 0xff000000) >> 24);
      p[5] = uint8_t((rip->entries[num].addr & 0x00ff0000) >> 16);
      p[6] = uint8_t((rip->entries[num].addr & 0x0000ff00) >> 8);
      p[7] = uint8_t(rip->entries[num].addr & 0x000000ff);

      p[8] = uint8_t((rip->entries[num].mask & 0xff000000) >> 24);
      p[9] = uint8_t((rip->entries[num].mask & 0x00ff0000) >> 16);
      p[10] = uint8_t((rip->entries[num].mask & 0x0000ff00) >> 8);
      p[11] = uint8_t(rip->entries[num].mask & 0x000000ff);

      p[12] = uint8_t((rip->entries[num].nexthop & 0xff000000) >> 24);
      p[13] = uint8_t((rip->entries[num].nexthop & 0x00ff0000) >> 16);
      p[14] = uint8_t((rip->entries[num].nexthop & 0x0000ff00) >> 8);
      p[15] = uint8_t(rip->entries[num].nexthop & 0x000000ff);

      p[16] = uint8_t((rip->entries[num].metric & 0xff000000) >> 24);
      p[17] = uint8_t((rip->entries[num].metric & 0x00ff0000) >> 16);
      p[18] = uint8_t((rip->entries[num].metric & 0x0000ff00) >> 8);
      p[19] = uint8_t(rip->entries[num].metric & 0x000000ff);

      p += 20;
    }
  }
  return length;
}
