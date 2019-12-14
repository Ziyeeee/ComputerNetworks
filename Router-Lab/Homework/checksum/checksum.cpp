#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint8_t *p;
  int headLen;
  unsigned long cksum = 0;
  p = packet + 2;
  if((size_t(p[0]<<8) + size_t(p[1])) == len)
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