"""TCP 单向字节流重组。

处理乱序到达、重传去重、重叠字节冲突检测与流内缺口检测。
序号空间以 SYN 的 ISN 为基准：首字节数据序号 = ISN + 1。
"""
from __future__ import annotations

from dataclasses import dataclass, field

WRAP = 1 << 32
HALF = 1 << 31


@dataclass
class StreamReassembler:
    """单方向 TCP 流重组器。"""

    isn: int
    segments: list[tuple[int, bytes]] = field(default_factory=list)

    def add(self, seq: int, data: bytes) -> None:
        if not data:
            return
        off = (seq - (self.isn + 1)) % WRAP
        if off >= HALF:
            # 序号落在 ISN 之前：同四元组上一化身连接的迟到报文，忽略，
            # 避免污染重新握手后的新连接。
            return
        self.segments.append((off, data))

    def assemble(self) -> tuple[bytes, list[tuple[int, int]], list[tuple[int, int]]]:
        """重组字节流。

        返回 (stream, gaps, conflicts)：
        - stream：按序号拼接的字节流（缺口处以 \\x00 占位，仅供定位）；
        - gaps：[(start, end)] 流内缺口（偏移区间）；
        - conflicts：[(start, end)] 重叠且字节不一致的区间（含冲突重传）。
        """
        buf = bytearray()
        pos = 0
        gaps: list[tuple[int, int]] = []
        conflicts: list[tuple[int, int]] = []
        # 同偏移时长段优先放置，短段随后按重传校验
        for off, data in sorted(self.segments, key=lambda s: (s[0], -len(s[1]))):
            end = off + len(data)
            if end <= pos:
                # 完全被覆盖：重传。逐字节校验一致性。
                if bytes(buf[off:end]) != data:
                    conflicts.append((off, end))
                continue
            if off > pos:
                gaps.append((pos, off))
                buf.extend(b"\x00" * (off - pos))  # 占位保持偏移对齐
                pos = off
            # 重叠区 [off, pos) 校验，追加 [pos, end)
            if bytes(buf[off:pos]) != data[: pos - off]:
                conflicts.append((off, pos))
            buf.extend(data[pos - off:])
            pos = end
        return bytes(buf), gaps, conflicts
