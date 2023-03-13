# News
Some security news I am interested in && have not done


#### v8
https://github.com/r4j0x00/exploits/tree/master/CVE-2020-16040  

https://mp.weixin.qq.com/s/O81Kw-ujcbjY_1S6dFKpxQ    
https://mp.weixin.qq.com/s/bYhQlblYxQRHqTb3zOrTew  



https://starlabs.sg/blog/2021/04/you-talking-to-me/  



安全客的几篇文章  

https://bugs.chromium.org/p/chromium/issues/detail?id=1126249  

https://gist.github.com/hkraw/5ba2df87925fb7de8acc3c4bcec4774e chrome v8 issue 1126249 poc  

https://securitylab.github.com/research/one_day_short_of_a_fullchain_renderer/ Chrome rce的最后一部分  



#### linux kernel1  
https://www.yuque.com/posec/public/sp9bs1  

https://github.com/xairy/linux-kernel-exploitation  

https://seclists.org/oss-sec/2021/q1/259?utm_source=dlvr.it&utm_medium=twitter CVE-2021-3444 Linux kernel bpf漏洞  






#### tools
LLVM
crix
AFL




#### windows 
d3ctf dheap


#### Linux kernel2  
https://paper.seebug.org/1889/#1  
https://bsauce.github.io/2022/11/11/CoRJail/#%E5%8F%82%E8%80%83  
https://www.ctfiot.com/75106.html  
https://www.ctfiot.com/76392.html  
2022 hitcon   
https://mp.weixin.qq.com/s?__biz=Mzg4MjcxMTAwMQ==&mid=2247485772&idx=1&sn=0f5b969f111d79027c59e6e2145698ef&chksm=cf53c9faf82440ec839aa7fc6b35bbc03251c824c5c5407ed9eb51181471d7514d651e3cfe97&mpshare=1&scene=23&srcid=12055uACFGja8KBjcPtP8ErG&sharer_sharetime=1670169963855&sharer_shareid=6eea79ff6da57fc6752ab0bc570bf392#rd  0x20 seq竞争泄露&提权
https://github.com/chompie1337/kernel_obj_finder kernel obj finder 指定大小进行obj寻找
https://interruptlabs.co.uk/labs/pipe_buffer/  pipe_buffer任意地址读写
https://lobste.rs/s/ch9civ  以 Linux 内核模块 Netfilter 的 UAF 漏洞为例，介绍如何编写针对 kmalloc-cg 对象的漏洞利用
https://blog.csdn.net/panhewu9919/article/details/118112795 可利用结构体总结
https://su-team.cn/passages/2023-01-10-RWCTF/  类似的double free内核题目

• [Linux] Exploiting null-dereferences in the Linux kernel:
https://googleprojectzero.blogspot.com/2023/01/exploiting-null-dereferences-in-linux.html
#### STL continer 逆向
https://www.ctfiot.com/76880.html  



#### VMware Workstation Pro(VM虚拟机) 17.0 官方版+永久激活密钥
http://t.qkhub.com/38uqw0  

• CVE-2022-31705:
https://github.com/s0duku/cve-2022-31705

   ・ VMware Workstation Heap OOB 漏洞POC。 – Atum

   

#### office CVE paper
https://mp.weixin.qq.com/s/lSggmLxW5aT3MGh0JFxn9w  
 

#### yara
https://www.ctfiot.com/77789.html  



#### Glibc heap
https://lexsd6.github.io/2021/05/02/heap%E6%B3%84%E9%9C%B2%E7%9C%9F%E5%AE%9E%E5%9C%B0%E5%9D%80tirck/  
noleak heap?  
https://blog.e4l4.com/posts/qwarmup/  
https://tttang.com/archive/1845/   ・ 基于IO_FILE的高版本glibc利用链 – xmzyshypnc  
https://blog.csdn.net/zzq487782568/article/details/127757201  
https://blog.wjhwjhn.com/archives/783/  
https://mp.weixin.qq.com/s?__biz=Mzg4MjcxMTAwMQ==&mid=2247485772&idx=1&sn=0f5b969f111d79027c59e6e2145698ef&chksm=cf53c9faf82440ec839aa7fc6b35bbc03251c824c5c5407ed9eb51181471d7514d651e3cfe97&mpshare=1&scene=23&srcid=12055uACFGja8KBjcPtP8ErG&sharer_sharetime=1670169963855&sharer_shareid=6eea79ff6da57fc6752ab0bc570bf392#rd IO_FILE vtable修改到了bss段
https://bbs.pediy.com/thread-275376.htm#msg_header_h2_1  strtok造成off-by-null  利用file 结构体进行泄露 沙箱绕过的学习
https://www.ctfiot.com/84178.html  给出pid之后 利用ptrace去写shellcode绕过沙箱
https://blog.wjhwjhn.com/archives/193/ 高版本off-by-null
https://www.reddit.com/r/netsec/comments/zuqu1h/overview_of_glibc_heap_exploitation_techniques/ 2.34以下的所有堆  
https://mp.weixin.qq.com/s?__biz=Mzg4MjcxMTAwMQ==&mid=2247486184&idx=1&sn=10a2a77f6636a9c75c4d9cff256ce3d6&chksm=cf53ca5ef8244348daf063ea6bd934c65eefbb3ab37588d1a299b1903fb963e27e516603f4be&mpshare=1&scene=23&srcid=030922bd4reoXuGOdpT1H8yH&sharer_sharetime=1678324408194&sharer_shareid=6eea79ff6da57fc6752ab0bc570bf392#rd house of 系列总结  

22.04 2.31
10  32
21.04 2.33
21.10 2.34

#### 异构 
https://www.cnblogs.com/winmt/articles/16842913.html  


#### chrome sandbox
2022 hitcon  
https://www.anquanke.com/post/id/283735 缓解指针  
bytectf  

#### v8
https://www.ctfiot.com/78944.html
2022 hitcon hole  https://chovid99.github.io/posts/hitcon-ctf-2022/#final-step
https://mp.weixin.qq.com/s/Q602eBLm-ExteVwIxq7uOg cve-2022-4262  
https://ju256.de/posts/kitctfctf22-date/ 一套题目


#### blink
• [Browser] 2358 - Chrome: heap-use-after-free in blink::LocalFrameView::PerformLayout (incomplete fix for CVE-2022-3199) - project-zero:
https://bugs.chromium.org/p/project-zero/issues/detail?id=2358

   ・ Chrome浏览器Blink组件UAF漏洞（CVE-2022-3654）细节，由project-zero的glazunov发现，是由于CVE-2022-3199漏洞错误修复导致的补丁绕过。 – P4nda



#### virtualbox
https://www.ctfiot.com/81562.html  



#### docker 逃逸
https://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247503697&idx=1&sn=e80099f488dd83f9d44a58a1df55bb74  

https://github.com/stealthcopter/deepce  5、deepce: Docker 枚举、特权升级和容器逃逸  

http://paper.vulsee.com/KCon/2021/Container%20escape%20in%202021.pdf  比较全的讲解pdf
https://su-team.cn/passages/2023-01-10-RWCTF/ binfmt解释器？

https://www.ctfiot.com/97725.html 容器逃逸手法实践

#### 渗透web
https://mp.weixin.qq.com/s/SqsaSoSdP3WTCf2NhoRujg SSRF SQL   



#### windows
bytectf  
https://voidsec.com/windows-exploitation-challenge-blue-frost-security-2022/


#### risc-v
https://arxiv.org/pdf/2211.16212.pdf JOP漏洞利用手法  
https://dl.acm.org/doi/10.1145/3545948.3545997 RiscyROP: Automated Return-Oriented Programming Attacks on RISC-V and ARM64

#### eaas
http://www.hackdig.com/11/hack-843024.htm hitcon



#### sqlite 
https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/



#### hitcon 
https://nightu.darkflow.top/posts/a60d8e49.html


#### lua
• LuaJIT Sandbox Escape: The Saga Ends:
https://0xbigshaq.github.io/2022/12/30/luajit-sandbox-escape/



#### CVE
[ TITLE] CVE提交流程（包含漏洞公开过程）
[ URL  ] http://t.qkhub.com/yvian1

Zabbix announces its public bug bounty program on HackerOne
https://www.zabbix.com/pr/pr439 



