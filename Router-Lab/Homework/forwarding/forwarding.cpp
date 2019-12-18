#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */

bool validateIPChecksum(uint8_t *packet, size_t len);

bool forward(uint8_t *packet, size_t len) {
  // TODO:
  uint8_t *p;
  int headLen;
  unsigned long cksum = 0;
  if(validateIPChecksum(packet, len))
  {
    p = packet + 8;
    if(p[0] > 0x00)
    {
      p[0] = p[0] - 1;
      p = packet;
      packet[10] = 0;
      packet[11] = 0;
      headLen = int((p[0]&0x0f)<<2);
      while (headLen > 0)
      {
        cksum += (uint16_t(p[0]<<8) + uint16_t(p[1]));
        p += 2;
        headLen -= 2;
      }
      cksum = (cksum>>16) + (cksum&0xffff);
      cksum += (cksum>>16);
      cksum = (uint16_t)(~cksum);
      packet[10] = uint8_t(cksum>>8);
      packet[11] = uint8_t(cksum&0x00ff);
      return true;
    }
    else
    {
      return false;
    }
  }
  else
  {
    return false;
  }
}

bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint8_t *p;
  int headLen;
  unsigned long cksum = 0;
  p = packet + 2;
  if(int((p[0]&0x0f)<<2) <= len)  //IP总长度
  {
    p = packet;
    headLen = int((p[0]&0x0f)<<2);
    while (headLen > 0)
    {
      cksum += (uint16_t(p[0]<<8) + uint16_t(p[1]));
      p += 2;
      headLen -= 2;
    }
    cksum = (cksum>>16) + (cksum&0xffff);
    cksum += (cksum>>16);
    cksum = uint16_t(cksum&0xffff);
    if (uint16_t(cksum) == 0xffff)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  else
  {
    return false;
  }
}