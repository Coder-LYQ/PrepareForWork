
# 1.注入
当攻击者将无效的数据发送给web应用程序来让其执行为设计的操作，就会发生代码注入问题。
此安全漏洞最常见的示例便是使用不受信任数据的SQL查询。代码注入漏洞的核心是缺乏对web应用程序使用的数据的验证和清理。任何接受参数作为输入的内容都可能受到代码注入攻击。

**危害：** 注入可以使数据丢失或者被破坏掉，并且缺乏可审计性或者拒绝服务。注入漏洞有时甚至可导致完全接管主机。

## 漏洞成因



## 如何进行防御代码注入漏洞
- 首选方法是使用**安全的API接口**，该API避免完全使用解释器，或者说提供参数化的接口或迁移为使用对象关系映射工具（ORM）。注意，即使说你参数化了，但是如果PL/SQL或者T-SQL连接查询和数据，或者说使用EXECUTE IMMEDIATE 或者exec()执行恶意数据，则存储过程仍然可以引入SQL注入。
- 使用**肯定或“白名单”**服务器端输入验证，由于许多应用程序都需要特殊字符，例如文本区域或者移动应用程序的API，因此这并不是一个完整的防御措施
- 对于任何残留的动态查询，请使用该解释程序的特定转义语法来转义特殊字符。注意，表名（table），列名（column），等SQL结构无法转义，因此用户提供的结构名很危险。这是报表编写软件中的常见问题。
- 在查询中**使用limit和其他SQL控件**可防止在SQL注入的情况下大量泄露记录（在被攻击后，能将受害程度降到最低，减少数据泄漏量）

## Conclusion
- 数据和web应用程序逻辑要分离；
- 实施限制，以在成功进行注入攻击的情况下限制数据公开。

# 2.失效身份验证和会话管理

身份验证漏洞可能让攻击者能尝试控制他们在系统中想要的任何账户，甚至更糟的是，获得对系统的完全控制。身份验证和会话管理失效通常是指在应用程序身份验证机制上发生的逻辑问题，例如恶意行为者暴力破解系统中的有效用户。
web应用程序包含一个失效身份验证和会话管理漏洞，如果它存在如下问题：

- 允许自动攻击，例如攻击者在其中拥有有效的用户名和密码的列表；

- 允许暴力破解或其他自动攻击；
- 允许使用默认密码，弱密码或者众所周知的密码。
- 使用薄弱或者无效的身份恢复以及忘记密码的过程，这是很不安全的；
- 使用纯文本，加密或弱哈希密码；
- 缺少或无效的多因素身份验证
- 在URL中公开会话ID
- 成功登录后不轮换会话ID

- 没有正确地让会话ID无效，用户会话或者身份验证令牌在注销或一段时间不活动期间未正确失效。

**危害**：
  可能导致部分甚至全部账户遭受攻击，一旦攻击成功，攻击者就能执行合法的任何操作。

**如何防范?**

多因素身份验证
弱密码检查，例如针对前10000个最差密码的列表尝试更改密码；
限制失败的登录尝试次数。记录所有故障，并在检测到暴力破解或者其他攻击时提醒管理员
使用服务器安全的内置会话管理器，该管理器在登录后生成具有较高熵的新随机会话ID。会话ID不应该位于URL中。ID应在注销，空闲和绝对超时后无效。

# 3.敏感信息泄露

敏感信息暴露是OWASP列表上最普遍的漏洞之一。它包括破坏应该受到保护的数据。

**如何防止数据泄露？**

1. 加强存储和传输所有的敏感数
2. 确保使用合适强大的标准算法和密钥，并且密钥管理到位
3. 确保使用密码专用算法存储密码
4. 及时清除没有必要存放的重要的敏感数据
5. 禁止自动收集敏感数据，禁用包含敏感数据的页面缓存。

# 4.XML外部实体注入攻击（XXE）

# 5.访问控制中断

# 6.安全性配置错误

# 7.跨站脚本攻击（XSS）

# 8.不安全的反序列化

# 9.使用具有已知漏洞的组件

# 10.日志记录和监控不足
