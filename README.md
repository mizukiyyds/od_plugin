所有操作的记录与结果均在od log窗口查看

#### **数据窗口右键功能**

1、直接提取字符串

![image-20230908013735871](https://github.com/mizukiyyds/od_plugin/tree/main/pic/1.png)

2、复制为字符数组

BYTE array[] = {
	0x00,0x00,0x00,0x00,0x8F,0x09,0x47,0x00,0xBE,0x09,0x47,0x00,0xF0,0x09,0x47,0x00,0x22,0x0A,0x47,0x00,
0x1D,0x9C,0x47,0x00,0x5D,0x9C,0x47,0x00,0x46,0x9D,0x47,0x00,0x18,0x9F,0x47,0x00,0x14,0xA1,0x47,0x00};

#### **CPU窗口右键功能**

![image-20230908013856127](https://github.com/mizukiyyds/od_plugin/tree/main/pic/2.png)

1、标签 选中一个 call 0x????????指令，给call的地址处一个名字

2、分配内存

插件使用VirtualAllocEx对进程分配一段指定大小的可读可写可执行的内存，并且会在数据窗口中转到内存的起始地址

3、合并区段式dump内存

比如有两个内存块

第1个内存块起始地址为0x10000大小为0x1000

第2个内存块起始地址为0x20000大小为0x1000

输入0x10000，0x21000即可保存这两个内存块（中间的数据用0填充）

4、跟踪至api

使用od trace功能一键跟踪，跟踪完毕后，cpu窗口会自动转到结束位置

![image-20230908014423476](https://github.com/mizukiyyds/od_plugin/tree/main/pic/3.png)

5、模拟至api
模拟完毕后，cpu窗口会自动转到结束位置（注意，并不是真实执行到了这里，任何数据都没有发生变化）

![image-20230908014505568](https://github.com/mizukiyyds/od_plugin/tree/main/pic/4.png)

6、通用iat修复

对当前cpu窗口的代码段进行扫描，并修复api调用

7、修复sp导入表

具体请参考视频或者我发的帖子
https://www.52pojie.cn/thread-1830972-1-1.html
https://share.weiyun.com/h1gSqpuG 密码52pj52

8、内存访问分析
模拟完毕后，cpu窗口会自动转到结束位置（注意，并不是真实执行到了这里，任何数据都没有发生变化）

![image-20230908014948418](https://github.com/mizukiyyds/od_plugin/tree/main/pic/5.png)

建议不管trace、模拟都可以用这个（除非速度慢或者log太多）具备antidump分析功能，直接系统调用分析功能

注意！！内存块数量、log打印会大幅影响效率

9、中断模拟器

当模拟器碰到死循环代码或者分析时长过长时，此选项可以中断5，8选项的模拟执行

10、模拟时hook cpuid

此选项可以控制 3、8选项模拟时的cpuid的返回值

点取消表示不改变已经设置好的值或默认
