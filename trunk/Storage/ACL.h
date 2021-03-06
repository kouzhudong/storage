/*
这里的安全主要是指文件安全，文件的安全即右键文件出现的安全标签，这主要是ACL.
ACL记得大致分DACL和SACL，具体是有ACE组成的。
ACE又分好多类，如：允许的，拒绝的，审计的等，ACE是由ACE_HEADER和ACCESS_MASK构成的。
宏观上是由SECURITY_DESCRIPTOR描述，这里包含了SID和ACL。
SID即用户。

所以，安全即是进程所代表的用户和文件所运行的用户之间的匹配。
这时安全的核心，也是攻防的核心。
实现办法：
1.修改进程所代表的用户，即提权。
2.修改文件所运行的用户，即篡改。
3.都是简介的，如：网络协议，漏洞等。

叫Security看上去很受欢迎，但是不如叫ACL专业。
*/

#pragma once
