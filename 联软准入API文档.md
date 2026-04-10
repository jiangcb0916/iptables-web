终端安全管理系统OPEN API服务接口规范文档V1.8

系统名称	终端安全管理系统OPEN API服务接口
项目负责人	吴海兵
作者
文档提交日期	2018-05-28

深圳市联软科技股份有权限公司
(版权所有,翻版必究)

修改记录

No	修改后
版本号	修改内容简介	修改日期	修改人

目 录
1	背景	6
2	规范适用对象说明	6
3	开通API权限	6
4	请求数据包格式规范	6
4.1	业务级参数的通用约定	6
4.2	接口安全访问说明	6
5	API接口细则	6
5.1	文件外发待审批信息查询接口	7
5.1.1	功能	7
5.1.2	参数	7
5.1.3	返回值	7
5.2	文件外发审批结果回传接口	9
5.2.1	功能	9
5.2.2	参数	9
5.2.3	返回值	9
5.3	LVFS文件下载接口	10
5.3.1	功能	10
5.3.2	参数	10
5.4	进程控制最近时间审计信息汇总查询接口	10
5.4.1	功能	10
5.4.2	参数	10
5.4.3	返回值	11
5.5	通知助手弹出消息的API接口	13
5.5.1	功能	13
5.5.2	参数	13
5.5.3	返回值	13
5.6	查询指定终端设备接口	14
5.6.1	功能	14
5.6.2	参数	14
5.6.3	返回值	15
5.7	根据策略名查询应用范围接口	16
5.7.1	功能	16
5.7.2	参数	16
5.7.3	返回值	16
5.8	增加策略应用范围接口	18
5.8.1	功能	18
5.8.2	参数	18
5.8.3	返回值	18
5.9	删除策略应用范围接口	20
5.9.1	功能	20
5.9.2	参数	20
5.9.3	返回值	21
5.10	根据策略范围ID删除策略范围接口	21
5.10.1	功能	21
5.10.2	参数	21
5.10.3	返回值	22
5.11	根据策略范围ID修改策略范围接口	22
5.11.1	功能	22
5.11.2	参数	23
5.11.3	返回值	23
5.12	查询审计信息的通用接口	24
5.12.1	功能	24
5.12.2	参数	24
5.12.3	返回值	26
5.13	补丁安装详细审计信息查询接口	27
5.13.1	功能	27
5.13.2	参数	27
5.13.3	返回值	28
5.14	管理员查询接口	29
5.14.1	功能	29
5.14.2	参数	29
5.14.3	返回值	29
5.15	管理员组查询接口	30
5.15.1	功能	30
5.15.2	参数	30
5.15.3	返回值	30
5.16	管理员新增接口	31
5.16.1	功能	31
5.16.2	参数	31
5.16.3	返回值	32
5.17	管理员修改接口	33
5.17.1	功能	33
5.17.2	参数	33
5.17.3	返回值	33
5.18	管理员删除接口	34
5.18.1	功能	34
5.18.2	参数	34
5.18.3	返回值	34
5.19	菜单树查询接口	35
5.19.1	功能	35
5.19.2	参数	35
5.19.3	返回值	35
5.20	部门树查询接口	36
5.20.1	功能	36
5.20.2	参数	36
5.20.3	返回值	36
5.21	管理员组新增接口	37
5.21.1	功能	37
5.21.2	参数	37
5.21.3	返回值	38
5.22	管理员组修改接口	38
5.22.1	功能	38
5.22.2	参数	38
5.22.3	返回值	39
5.23	管理员组删除接口	39
5.23.1	功能	39
5.23.2	参数	39
5.23.3	返回值	40

1	背景
本文旨在为第三方合作系统提供统一的HTTP接口调用与交互规范,通过该接口实现第三方的合作系统与终端安全管理系统的无缝对接。

2	规范适用对象说明
本规范仅适用于由服务器端发起调用请求、POST提交数据以及GET请求文本数据结果的Open API。
该接口具有以下特点：
- 基于HTTP协议
- 通过json格式返回数据

3	开通API权限
申请的方法请联系深圳市联软科技股份有限公司。

4	请求数据包格式规范

4.1	业务级参数的通用约定
表格 4-2 业务级参数的通用约定
参数名	类型	描述
status	String	用于判定操作状态SUCCESS 成功；ERROR 失败 ; INVALID 无权限
msg	String	结果说明
rows	JSON	返回结果集

4.2	接口安全访问说明
接口调用必须配置允许访问接口的第三方系统服务IP地址
将下列配置新增在联软管控平台系统的Ini/ config.properties中：
WhiteListServerIp=xxx.xxx.xxx.xxx;xxx.xxx.xxx.xxx

5	API接口细则
以下接口返回数据均是以JSON格式为demo，JSON格式的字符串内容是JSON输出数据所对应的HTM的标准JSON字符串。

5.1	文件外发待审批信息查询接口

5.1.1	功能
外部应用调用，用于获取待审批的文件外发待审批信息。
URL Demo：
http://{IP}:30098/fileoutsend?act=queryApprovedRecords

5.1.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
type	String	外发类型：1.打印，2.虚拟磁盘，3.刻录，4.邮件外发，5.文件读写审计策略(不传表示查所有类型待审批数据)多种类型用逗号“,”隔开 	非必要
mark	String	mark=all标记返回所有数据，否则返回上次查询时间到当前时间的记录	非必要

5.1.3	返回值
- Response JSON 示例
{
"rows":[{
"uidapplyid":"","strusername":"","struserdesc":"","strrolename":"","strroledesc":"","strrolenamepaths":"","strdevname":"","strdevip":"","strmac":"","strapplicationreason":"","dttime":"","itype":5,"isubtype":0,"uidlvfsserverid":"","strdownloadpath":"","strfilename":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
total	Int	结果数据的数量
rows	JSON	文件外发待审批信息详细"uidapplyid":"",/**待审核信息记录的id**/"strusername":"",/**用户名**/"struserdesc":"",/**用户全名**/"strrolename":"",/**用户所属部门名称**/"strroledesc":"",/**用户所属部门描述**/"strrolenamepaths":"",/**用户所属部门全路劲**/"strdevname":"",/**设备名称 **/"strdevip":"",/**设备IP地址**/"strmac":"",/**设备MAC地址 **/"strapplicationreason":"",/**待审核信息的用户申请理由**/"dttime":"",/**待审核记录的上报时间 **/"itype":, /**待审核记录的类型 1.打印，2.虚拟磁盘，3.刻录，4.邮件外发，5.文件读写审计策略**/"isubtype":0, 	当itype=1时，isubtype值：[1:受控数据盘,2:非受控数据盘,3:业务系统]	当itype=2时，isubtype值：[1:进盘,2:出盘]	当itype=3时，isubtype值：[1:受控数据盘,2:非受控数据盘]	当itype=4时，isubtype值：[ 0:所有 ]
当itype=5时，isubtype值：[ 0:所有 ]
"uidlvfsserverid":"",/**待审核文件存放的服务器配置ID**/"strdownloadpath":"",/**待审核文件的下载路劲**/"strfilename":""/**待审核文件名称**/

5.2	文件外发审批结果回传接口

5.2.1	功能
外部应用调用，用于将文件外发的待审批信息的审批结果回传到联软终端安全管理系统。
URL Demo：
http://{IP}:30098/fileoutsend?act=updateApproveResult

5.2.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
uidapplyid	String	审批记录id	必要
iapprovalresult	String	审批结果：1同意，0拒绝	必要
strremark	String	审批备注	非必要

5.2.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 参数说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

5.3	LVFS文件下载接口

5.3.1	功能
外部应用调用，可获取某个待审批外发文件的内容。
URL Demo：
http://{IP}:30098/fileoutsend?act=downloadFileAttach

5.3.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
uidlvfsserverid	String	lvfs下载服务器id	必要
encodelvfspath	String	文件lvfs下载路径的base64编码	必要

5.4	进程控制最近时间审计信息汇总查询接口

5.4.1	功能
主要查询返回查询条件内的同一设备同一进程的最近一个时间的记录数据
URL Demo：
http://{IP}:30098/terminalaudit?act=queryProcessControlAuditInfo

5.4.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体
strtime	String	查询时间段:
2018-06-01 08:30:00|2018-06-01 09:30:00有效分发时间以|竖线分割，只有一个时间时，则默认为起始时间至当前时间。
若此参数不传递，则默认查询当天0点开始至调用接口时的当前时间。
conditionID	String	记录查询条件的key值，用于分页的时候保持上次的查询条件（第一次查询时不需要带此参数）
page	String	请求分页数据的页码（第一次查询时不需要带此参数）
strdevip	String	设备IP地址
strmac	String	设备MAC地址
strusername	String	设备用户名

5.4.3	返回值
- Response JSON 示例
{
"rows": [{}],
"total": 10000,
"conditionID": "xxxxx"
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 参数说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
conditionID	String	映射查询条件的key值（下次查询带上这个可以值以及分页页码即可返回这次查询条件内的指定页码的数据）
total	String	查询条件内的记录总数
rows	String	查询时间内的同一设备同一进程的最近一个时间的记录
返回的字段有strdevname，strdevip，strmac，strusername，uidroleid，strrolename，dttime，Strfilefull，strcompandname，strproductname，strorgname，strfiledesc，strfileversion表字段说明如下：//进程控制审计create table tbl_processcontrolauditinfo(
uidrecordid varchar(128) ,//记录ID，唯一
uiddomainid varchar(128),//域ID。每个行政管理域的唯一标示，如上海分公司和北京分公司就是两个不同的地域
strdomainname varchar(256), //管理域名称
uiddevrecordid varchar(128),//设备ID，每台设备的唯一标识
stragentid varchar(128), //助手id
strdevname varchar(256), //设备名称
strdevalias varchar(1024),//设备别名
strdevip varchar(128), //设备ip
strip1 varchar(128) ,//long型的设备IP，用于排序
strmac varchar(64), //mac地址
strnet varchar(256),//网段
uiduserid varchar(128), //用户id
strusername varchar(256), //用户名称
struserdes varchar(256), //用户描述
uidroleid varchar(128), //部门id
strrolename varchar(128), //部门名称
dttime timestamp part,//发生时间
uidsecpolicyid varchar(128) ,//策略ID，标记是由哪个策略产生的审计信息
strsecpolicyname varchar(256) ,//策略名称
isecpolicytype int4 ,//策略类型 每种策略的一个唯一类型
strfilefull varchar(2048) ,//文件全路径
iagentonline int2 ,//助手在线 1=在线 0=离线
iblock int2 ,//是否阻止 1=阻止 0=未阻止
iaction int4 ,//1=启动 0=停止
strsystemuser varchar(256) ,//系统用户：如：windows账户名称
ipid int4,//进程pid
iexebits int4,//进程32 or 64 位，数据库存32或64
imemkb int8,//占用内存数 单位KB
strprocessuser varchar(256) ,//进程用户
strcompandname varchar(256) ,//公司名
strproductname varchar(256) ,//产品名
strorgname varchar(256) ,//源文件名
strfiledesc varchar(1024) ,//文件描述
strfileversion varchar(128) ,//文件版本
strfilemd5 varchar(128) , //MD5
dtinserttime timestamp//记录插入时间
);

5.5	通知助手弹出消息的API接口

5.5.1	功能
根据客户发送的信息通知助手弹出消息
URL Demo：
http://{IP}:30098/terminal?act=noticeAgentMsg

5.5.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
querytype	String	查询设备类型：
0：设备IP1：MAC地址2：设备名称3：用户名	必填
queryvalue	String	查询设备值，与querytype对应。多个值之间用“;”分隔。	必填
popmsg	String	需要弹出的消息。	必填
autoclose	String	消息是否自动关闭。0：自动关闭，1：不自动关闭。默认值是0。
isrepeat	String	是否反复弹出消息。0：否，1：是。默认值是0。
repeattime	String	反复弹出的时间间隔，单位：秒。	如果isrepeat不为空，此项必填。

5.5.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

5.6	查询指定终端设备接口

5.6.1	功能
按条件查询已安装联软客户端的终端设备。
URL Demo：
http://{IP}:30098/terminal?act=queryDevByParams

5.6.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
terminaltype	String	查询类型0:所有设备1:已安装终端设备 2:未安装终端设备 默认是1
paramstype	String	参数类型1:设备名，模糊查询包含设备名的设备信息2:设备IP，精准查询设备IP的设备信息3:设备MAC，精准查询设备MAC的设备信息4:部门，精准查询部门下的所有设备信息
5:用户名，精准查询用户名所属的设备信息
paramsvalue	String	具体参数值，详细说明如下：1:设备名，多个用户名之间用“;”分隔。2:设备IP 多个IP之间用“;”分隔。
3:设备MAC 多个MAC之间用“;”分隔。4:部门
例如: AAC->长沙办->测试。多个部门之间用“;”分隔。5:用户名多个用户名之间用“;”分隔。
containsubrole	String	当paramstype=4时有效
containsubrole=true时表示查询子部门，否则不查询子部门

5.6.3	返回值
- Response JSON 示例
{
"rows":[{
"istatus":"","strdevname":"","strdevip":"","strmac":"","strdeptname":"","strusername":"","struserdes":"","strswitchname":"","strifname":"","strmail":""," strphone":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的设备信息表字段说明如下： status int4 状态 1:助手在线 2:助手离线 3:未装助手
strdevname varchar(256) 设备名称
strdevip varchar(128) 设备IP
strmac varchar(28) MAC地址
strdeptname varchar(128) 部门名称
strusername varchar(128) 认证名
struserdes varchar(128) 用户姓名
strswitchname varchar(256) 网络设备
strifname varchar(256) 端口
strmail varchar(256) 电子邮箱
strphone varchar(20) 电话号码

5.7	根据策略名查询应用范围接口

1.1.1	功能
实现通过策略名查询该策略的应用范围。
URL Demo：
http://{IP}:30098/secpolicy?act=getSecScopeByName

1.1.1	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
secpolicyname	String	策略名称	必填

1.1.1	返回值
- Response JSON 示例
{
"rows":[{
"uidsecpolicyid":"","uidscopeid":"","secpolicyname":"","stros":"","strlan":"","strdesc":"","scopytype":"","value1":"","value2":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的策略范围信息
表字段说明如下：
uidscopeid varchar(48) ,//应用范围记录ID，唯一
uidsecpolicyid varchar(48),//策略id
secpolicyname varchar(256), //策略名称
stros varchar(128),//操作系统
strlan varchar(128), //语言
strdesc varchar(1024), //描述
scopetype int4,//范围类型
value1 varchar(128),//值1(scopeType不同代表不同含义)
value2 varchar(128)//值2(scopeType不同代表不同含义)
注意：scopetype，value1和value2三者关系及含义详见表5-1-1

- 范围类型和对应值关系说明
范围类型值	范围类型含义	value1 	value2
0	设备-所有设备	无	无
5	设备-设备名称	设备名	无
1	设备-设备IP	起始IP地址	结束IP地址
11	设备-MAC地址	MAC地址	MAC地址
2	设备-网段	网段	无
6	设备-设备组	设备组名称	无
3	用户-所属部门	部门结构,例如：Root->长沙办	1:包含子部门2:不包含子部门
9	用户-用户	用户账户	用户名称
15	用户-用户组	用户组名称	无
4	例外设备-设备IP	起始IP地址	结束IP地址
12	例外设备-MAC地址	MAC地址	MAC地址
7	例外设备-设备组	设备组名称	无
10	例外用户-用户	用户账号	用户名称
16	例外用户-用户组	用户组名称	无
13	例外设备-指定设备	设备ID	设备IP
表5-1-1

1.1	增加策略应用范围接口

1.1.1	功能
对某个策略增加应用范围。
URL Demo：
http://{IP}:30098/secpolicy?act=addSecpolicyScope

1.1.1	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
secpolicyname	String	策略名称	必填
scopetype	Integer	范围类型，具体含义详见表5-1-2	必填
value	String	根据scopeType不同表示不同含义，详见表5-1-2
strdesc	String	描述
extrastarttime	String	例外开始生效时间，格式:yyyy-MM-dd HH:mm。例如:2018-11-10 12:01
extraendtime	String	例外结束生效时间，格式:yyyy-MM-dd HH:mm。例如:2018-11-10 12:01

1.1.1	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功",
"rows":[{
"uidscopeid":""
},…{…
}]
}
或者
{
"status": "ERROR",
"msg": "失败、缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 参数说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	表字段说明如下：
uidscopeid varchar(48) ,//应用范围记录ID，唯一

- 范围类型和对应值关系说明
范围类型值	范围类型含义	value	startTime	endTime
0	设备-所有设备	无	无	无
5	设备-设备名称	设备名称	无	无
1	设备-设备IP	IP地址,可传范围,中间用“-”分开，例如:192.168.1.1-192.168.1.5。也可以传多个Ip地址，中间用“;”分割，例如192.168.1.1,192.168.1.2。	无	无
11	设备-MAC地址	MAC地址,可传多个，中间用“;”隔开。例如FF:FF:FF:FF:FF;GG:GG:GG:GG:GG:GG	无	无
2	设备-网段	网段信息，例如：169.254.0.0/16
可以传多个,中间用“;”分割	无	无
6	设备-设备组	设备组名
可以传多个,中间用“;”分割	无	无
3	用户-所属部门	格式：A,B(A和B表示含义如下)
A：部门
B:1 包含子部门2 不包含子部门
例如: AAC->长沙办->测试,1
可以传多个,中间用“;”分割	无	无
9	用户-用户	用户账号,格式A,B（A:用户账号,B:用户名）
可以传多个,中间用“;”分割	无	无
15	用户-用户组	用户组名
可以传多个,中间用“;”分割	无	无
4	例外设备-设备IP	IP地址,可传范围,中间用“-”分开，例如:192.168.1.1-192.168.1.5。也可以传多个Ip地址，中间用“;”分割，例如：192.168.1.1;192.168.1.2。	例外开始时间	例外结束时间
12	例外设备-MAC地址	MAC地址,可传多个，中间用“;”隔开。例如FF:FF:FF:FF:FF,GG:GG:GG:GG:GG:GG	例外开始时间	例外结束时间
7	例外设备-设备组	设备组名
可以传多个,中间用“;”分割	例外开始时间	例外结束时间
10	例外用户-用户	用户账号,格式A,B（A:用户账号,B:用户名）
可以传多个,中间用“;”分割	例外开始时间	例外结束时间
16	例外用户-用户组	用户组名
可以传多个,中间用“;”分割	例外开始时间	例外结束时间
17	例外设备-设备名	设备名称
可以传多个,中间用“;”分割	例外开始时间	例外结束时间
表5-1-2

1.1	删除策略应用范围接口

1.1.1	功能
实现通过条件删除策略应用范围。
URL Demo：
http://{IP}:30098/secpolicy?act=delSecpolicyScope

1.1.1	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
secpolicyname	String	策略名称	必填
scopetype	String	范围类型，具体值详见表5-1-1	必填
value1	String	具体含义根据scopeType改变，详见表5-1-1
value2	String	具体含义根据scopeType改变，详见表5-1-1

1.1.1	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.1	根据策略范围ID删除策略范围接口

1.1.1	功能
根据策略范围的ID来删除该策略范围。
URL Demo：
http://{IP}:30098/secpolicy?act=delSecpolicyScopeById

1.1.1	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
scopeid	String	策略范围ID
参见如下接口的返回值定义：	必填

1.1.1	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.1	根据策略范围ID修改策略范围接口

1.1.1	功能
根据策略范围的ID来修改该策略范围。
URL Demo：
http://{IP}:30098/secpolicy?act=updateSecpolicyScopeById

1.1.1	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
scopeid	String	策略范围ID
参见如下接口的返回值定义	必填
scopetype	Integer	范围类型，具体含义详见表5-1-1	必填
value1	String	根据scopeType不同表示不同含义，详见表5-1-1
value2	String	根据scopeType不同表示不同含义，详见表5-1-1
strdesc	String	描述
extrastarttime	String	例外开始生效时间，格式:yyyy-MM-dd HH:mm。例如:2018-11-10 12:01
extraendtime	String	例外结束生效时间，格式:yyyy-MM-dd HH:mm。例如:2018-11-10 12:01

1.1.1	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.1	查询审计信息的通用接口

1.1.1	功能
根据条件获取审计信息。
主要支持目前的所有通用审计信息
URL Demo：
http://{IP}:30098/auditinfo?act=queryCommonAuditInfo

1.1.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
strinfotype	String	查询的审计信息表tbl_processcontrolauditinfo：进程控制审计信息tbl_fileoperateauditinfo：文件读写操作审计信息tbl_webcontrolauditinfo：上网审计信息tbl_immediatechataudit：即时聊天审计
tbl_sensitiveauditinfo：敏感文件审计
tbl_emailcontrolauditinfo：邮件审计
tbl_ftpaccessauditinfo：ftp访问控制审计tbl_printcontrolauditinfo：打印控制审计
tbl_selfcheckreport：系统自检审计
tbl_toolboxauditinfo：工具使用审计
tbl_networkconnectauditcontrolinfo：网络连接控制与审计
tbl_filetrackmarkinfo：文档追踪审计
tbl_swdistrexecinfo：软件分发执行审计
tbl_processmonitorauditinfo：进程监视审计
tbl_screenauditinfo：屏幕操作审计
tbl_agentselfupdateinfo：安全助手升级审计
tbl_netabauditinfo：网络异常审计
tbl_notifymsgauditinfo：消息通知审计
tbl_safediskoprauditinfo：安全U盘控制审计
tbl_softwareuselongauditcontrolinfo：软件使用时长审计
tbl_advancedtermprotectauditcontrolinfo：防勒索审计
tbl_terminalstandardauditcontrolinfo：终端标准化审计
tbl_osacctchangeauditinfo：操作系统账号变更审计
tbl_oseventlogauditinfo：操作系统日志审计
tbl_servicechangeauditinfo：服务变更审计
tbl_autorunchangeauditinfo：自动运行项变更审计
tbl_unexpectbehaviorauditinfo：非预期行为审计
tbl_socketchangeauditinfo：套接字服务变更审计
tbl_remoteassistanceauditcontrolinfo：远程协助审计
tbl_usbkeyauditinfo：UKey用户登录审计
tbl_aclfirewallauditinfo：网络资源访问控制审计tbl_businesssysdlpauditinfo：业务数据防泄漏审计tbl_screenvectorwaterinfo：屏幕矢量水印审计tbl_braiseprogramreportrt：Braise运行时信息tbl_aclregaccessauditinfo：注册表访问审计tbl_braiseprogramauditinfo：Braise脚本策略执行结果tbl_enesavemgrreport：节能管理审计
tbl_unauthconninfo：非授权外连审计	必填
strtime	String	查询时间段:
2018-06-01 08:30:00|2018-06-01 09:30:00有效分发时间以“|”竖线分割，只有一个时间时，则默认为起始时间至当前时间。若此参数不传递，则默认查询当天0点开始至调用接口时的当前时间。
conditionid	String	单次查询条件的唯一值，用于分页返回数据时，多次查询调用需要保持上次的查询条件（第一次查询时不需要带此参数）
column	String	查询审计信息的字段名称
格式为：columnname1,columnname2……Eg: strusername,dttime
参数为空则默认返回对应审计信息表的完整字段数据
参见下表定义说明
page	String	请求分页数据的页码（第一次查询时不需要带此参数），默认从1开始	当conditionid存在时，则page参数必填
num	String	每次请求返回的最大数据条数，默认2000
该值单次查询条件后不能再次修改。
strdevip	String	设备IP地址
strmac	String	设备MAC地址
strusername	String	设备用户名
uidsecpolicyid	String	策略id
strsecpolicyname	String	策略名称
criteria	String	自定义查询条件，例如：and strdevip!=''

1.1.3	返回值
- Response JSON 示例
{
"rows": [{}],
"total": 10000,
"conditionid": "xxxxx"
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 参数说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
conditionid	String	单次查询条件的唯一值（如果查询数据过多，需要多次查询时，下次查询带上这个值以及分页页码即可返回这次查询条件内的指定页码的数据）
total	String	查询条件内的记录总数
rows	String	返回满足条件的记录数据

1.2	补丁安装详细审计信息查询接口

1.2.1	功能
主要查询返回查询条件内的设备安装补丁详细信息的记录数据
URL Demo：
http://{IP}:30098/terminalaudit?act=queryClientPatchAuditInfo

1.2.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
strtime	String	查询时间段:
2018-06-01 08:30:00|2018-06-01 09:30:00有效分发时间以“|”竖线分割，只有一个时间时，则默认为起始时间至当前时间。若此参数不传递，则默认查询当天0点开始至调用接口时的当前时间。
conditionid	String	单次查询条件的唯一值，用于分页返回数据时，多次查询调用需要保持上次的查询条件（第一次查询时不需要带此参数）
page	String	请求分页数据的页码（第一次查询时不需要带此参数），默认从1开始	当conditionid存在时，则page参数必填
num	String	每次请求返回的最大数据条数，默认2000
该值单次查询条件后不能再次修改。
strdevip	String	设备IP地址
strmac	String	设备MAC地址
strusername	String	设备用户名

1.2.3	返回值
- Response JSON 示例
{
"rows":[{
"strtitle":"","strkb":"","strusername":"","struserdes":"","strdeptname":"","strdevname":"","strdevip":"","strmac":"","istate":"","iinstallexitcode":"","dtinstalltime":"","iisinstallbyagent":"","ismspatch":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的设备信息表字段说明如下： strtitle varchar(128) 更新标题strkb varchar(128) KB号strusername varchar(128) 用户名struserdes varchar(128) 用户全名strdeptname varchar(128) 部门名称strdevname varchar(128) 设备名称strdevip varchar(128) 设备IPstrmac varchar(128) MAC地址istate int(4) 安装状态iinstallexitcode varchar(128) 错误码dtinstalltime timestamp 安装时间iisinstallbyagent varchar(128) 补丁安装来源ismspatch varchar(128) 是否是在库补丁

1.3	管理员查询接口

1.3.1	功能
根据管理员名称和所属组查询管理员信息。
URL Demo：
http://{IP}:30098/operator?act=queryOperator

1.3.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
searchtype	String	检索条件类型,1：管理员名2：用户组名
searchkey	String	检索条件关键字

1.3.3	返回值
- Response JSON 示例
{
"rows":[{
"stroperatorname":"","strdesc":"","uidopergroupid":"","uidoperatorid":"","stropergroupname":"","startip":"","endip":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的管理员信息表字段说明如下： stroperatorname varchar(128) ,//管理员账号
strdesc varchar(128),//描述
uidopergroupid varchar(48), //所属组id
uidoperatorid varchar(48),//管理员id
stropergroupname varchar(128), //管理员组名startip varchar(128), //起始IP地址 endip varchar(128),//结束IP地址

1.4	管理员组查询接口

1.4.1	功能
根据管理员组名称和描述查询管理员组信息。
URL Demo：
http://{IP}:30098/operator?act=queryOperatorGroup

1.4.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
searchtype	String	检索条件类型,1：管理员组名2：描述
searchkey	String	检索条件关键字

1.4.3	返回值
- Response JSON 示例
{
"rows":[{
"uidopergroupid":"","stropergroupname":"","strdesc":""
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的管理员信息表字段说明如下：
uidopergroupid varchar(48), //所属组id
stropergroupname varchar(128), //管理员组名strdesc varchar(128),//描述

1.5	管理员新增接口

1.5.1	功能
实现管理员的新增操作。
URL Demo：
http://{IP}:30098/operator?act=saveOperator

1.5.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatoraccount	String	管理员账号	必填
groupname	String	所属组名称	必填
accounttype	String	账号类型,1:本地账号	必填
operatorpwd	String	账号密码(明文传递过来，接口再加密)	必填
strdesc	String	描述
operatoremail	String	邮箱
operatorphone	String	电话
startip	String	起始Ip地址	和endip必须同时不为空，否则会被忽略。
endip	String	结束IP地址	和startip必须同时不为空，否则会被忽略。
ipstarttime	String	账户允许使用开始时间，格式yyyy-MM-dd
ipendtime	String	账户允许是用结束时间，格式yyyy-MM-dd
ipdesc	String	ip限制描述

1.5.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.6	管理员修改接口

1.6.1	功能
实现管理员的修改操作。
URL Demo：
http://{IP}:30098/operator?act=updateOperator

1.6.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatorid	String	管理员ID	必填
operatoraccount	String	管理员账号	必填
groupname	String	所属组名称	必填
accounttype	String	账号类型,1:本地账号	必填
operatorpwd	String	账号密码(明文传递过来，接口再加密)	必填
strdesc	String	描述
operatoremail	String	邮箱
operatorphone	String	电话
startip	String	起始Ip地址
endip	String	结束IP地址
ipstarttime	String	账户允许使用开始时间，格式yyyy-MM-dd
ipendtime	String	账户允许是用结束时间，格式yyyy-MM-dd
ipdesc	String	ip限制描述

1.6.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.7	管理员删除接口

1.7.1	功能
实现管理员的删除操作。
URL Demo：
http://{IP}:30098/operator?act=deleteOperator

1.7.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatorid	String	管理员Id	必填

1.7.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.8	菜单树查询接口

1.8.1	功能
返回所有菜单信息，返回时组装成父子节点。
URL Demo：
http://{IP}:30098/operator?act=queryMenuTree

1.8.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）

1.8.3	返回值
- Response JSON 示例
{
"rows":[{
" id ":""," text ":""," leaf ":""," children":"[{" id ":""," text ":""," leaf ":""}]"
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	字段说明如下：
id String, //菜单id
text String, //菜单名字leaf Boolean,//是否是叶子节点，true:是 false:否isButton Boolean,//是否是功能按钮。true:是 false:否
children Object,//孩子节点数据

1.9	部门树查询接口

1.9.1	功能
返回所有部门信息，返回时组装成父子节点。
URL Demo：
http://{IP}:30098/operator?act=queryDeptTree

1.9.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
parentdeptid	String	父类部门ID，查询出该部门信息和所有一级子部门信息，不填默认根节点。

1.9.3	返回值
- Response JSON 示例
{
"rows":[{
" id ":""," text ":""," leaf ":""," children":"[{" id ":""," text ":""," leaf ":""}]"
},…{…
}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	字段说明如下：
id String, //部门id
text String, //部门名children Object,//孩子节点数据

1.10	管理员组新增接口

1.10.1	功能
实现管理员组的新增功能。
URL Demo：
http://{IP}:30098/operator?act=addOperatorGroup

1.10.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatorgroupname	String	管理员组名称	必填
operatorgroupdesc	String	管理员组描述
menuids	String	该组拥有的菜单权限，会自动包含其下所有子菜单。多个菜单id之间用“,”隔开，例如: fff7,eff7
buttonids	String	该组拥有的所有具体功能id，多个之间用,隔开。
deptids	String	该组拥有的部门权限。多个部门ID之间用“,”隔开，例如: abb2,ccc-

1.10.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.11	管理员组修改接口

1.11.1	功能
实现管理员组的修改功能。
URL Demo：
http://{IP}:30098/operator?act=updateOperatorGroup

1.11.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatorgroupid	String	管理员组ID	必填
operatorgroupname	String	管理员组名称	必填
operatorgroupdesc	String	管理员组描述
menuids	String	该组拥有的菜单权限，会自动包含其下所有子菜单。多个菜单id之间用“,”隔开，例如: fff7,eff7
buttonids	String	该组拥有的所有具体功能id，多个之间用,隔开。
deptids	String	该组拥有的部门权限。多个部门ID之间用“,”隔开，例如: "abb2","ccc-"

1.11.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.12	管理员组删除接口

1.12.1	功能
实现管理员组的删除功能。
URL Demo：
http://{IP}:30098/operator?act=deleteOperatorGroup

1.12.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
operatorgroupid	String	管理员组ID	必填

1.12.3	返回值
- Response JSON 示例
{
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明

1.13	终端信息查询接口

1.13.1	功能
根据助手id查询终端信息。
URL Demo：
http://{IP}:30098/terminal?act=queryterminalinfo

1.13.2	参数
参数名	类型	描述	必要性
5.2.1 系统级参数全体
5.2.2 业务级参数全体（注意：参数名称全为小写）
agentid	String	助手id	必填

1.13.3	返回值
- Response JSON 示例
{
"rows":[{}],
"total": 3,
"status": "SUCCESS",
"msg": "成功"
}
或者
{
"status": "ERROR",
"msg": "失败"、"缺少必要参数或者参数无效"
}
或者
{
"status": "INVALID",
"msg": "无权限"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 无权限
msg	String	结果说明
rows	String	符合查询条件的设备信息返回字段说明如下：
strdevidentiy varchar(128) 助手id
strdevname varchar(256) 设备名称
strdevip varchar(128) 设备IP
strmac varchar(28) MAC地址stros varchar(128) 操作系统
strversion varchar(128) 操作系统版本
dtosinstalltime timestamp 操作系统安装时间strvendor varchar(128) 制造商strmainboardtype varchar(128) 型号strmbserialnumber varchar(128) 序列号strcputype varchar(128) cpu型号
ifhdsize int 硬盘大小，单位(kb)icurrentmemmb int 内存大小，单位(kb)

1.14	免检设备接口

1.14.1	MAC免检设备新增、编辑接口

1.14.1.1	功能
调用接口，新增或者编辑免检设备：当如下4.1.1参数章节中的mac_start与mac_end参数存在时，则是编辑免检设备，否则为新增免检设备。
URL Demo：
http://{IP}:30098/devAccessAllowed?act=addByMac

1.14.1.2	参数
参数名	类型	描述	必要性
mac_start	String	免检设备的开始mac范围格式示例：
mac=00:CF:E0:53:A0:00 mac=00-CF-E0-53-A0-00	必填
mac_end	String	免检设备的截止mac范围格式示例：
mac=00:CF:E0:53:A0:F8
mac=00-CF-E0-53-A0-F8	选填(不填时，则该字段等于mac_start）
dept	String	免检设备的部门名称 格式示例：
dept=测试部门	选填（部门名称如果有重名则采用多级部门的方式）
separate	String	多级部门的分隔符
格式示例： separate= ->	选填（多级部门的分隔符（选填）默认 “ -> ”）
user	String	免检设备的所属用户格式示例：user=root	选填
devtype	String	免检设备的设备类型格式示例：devtype=笔记本	选填
time_scope	String	免检设备的有效期起止时间
格式示例：time_scope=2019-10-10 00:00:00-2021-10-22 23:59:59	选填
acl	String	免检设备应用的ACL
格式示例：acl=UACL_NAH	选填
vlan	String	免检设备应用的vlan格式示例：vlan=vlan1	选填
ciscophone	String	是否为思科IP电话接入
格式示例：ciscophone=0	选填(取值范围[0|1],0代表否,1代表是,默认否)
desc	String	免检设备的备注信息
格式示例：desc=mac免检设备	选填

1.14.1.3	返回值
- Response JSON 示例
1.14.1.3.1	调用成功
{
"status": "SUCCESS",
"msg": "Interface call succeeded"
}
1.14.1.3.2	调用失败
{
"status": "ERROR",
"msg": "mac_start不能为空！"
}
或者
{
"status": "INVALID",
"msg": "request invalid"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 非法请求
msg	String	结果说明

1.14.1.3.3	调用接口失败详解
1.14.1.3.3.1	ERROR
当用户调用接口时，会对参数做校验，检验出的参数不规范时，返回的Response JSON的status为ERROR,当没有填写mac_start时格式如下
{
"status": "ERROR",
"msg": "mac_start不能为空！"
}
msg错误描述
当接口参数的校验失败：

参数名 校验类型 msg
mac_start 格式校验 mac_start参数格式有误！
必填校验 mac_start不能为空！
mac_end 格式校验 mac_end参数格式有误！
范围校验 mac_end不小于mac_start!
dept 存在校验 不存在部门:{0}
user 存在校验 不存在用户:{0}!
devtype 存在校验 不存在设备类型:{0}!
time_scope 格式校验 time_scope参数格式有误！
范围校验 time_scope截止时间不小于截止时间!
acl 存在校验 不存在ACL:{0}!
vlan 存在校验 不存在VLAN:{0}!
ciscophone 格式校验 ciscophone参数格式有误！
1.14.1.3.3.2	INVALID
参考3.2接口安全访问说明，如果您的ip地址没有在配置在WhiteListServerIp的范围中，则返回的Response JSON的status为INVALID,格式如下
{
"status": "INVALID",
"msg": "request invalid"
}

1.14.2	删除MAC免检设备接口

1.14.2.1.1	功能
调用接口，删除MAC地址形式的免检设备
URL Demo：
http://{IP}:30098/devAccessAllowed?act=delByMac

1.14.2.1.2	参数
参数名	类型	描述	必要性
mac_start	String	免检设备的开始mac范围格式示例：
mac=00:CF:E0:53:A0:00 mac=00-CF-E0-53-A0-00	必填
mac_end	String	免检设备的截止mac范围格式示例：
mac=00:CF:E0:53:A0:08 mac=00-CF-E0-53-A0-08	选填(不填时，则该字段等于mac_start）

1.14.2.1.3	返回值
- Response JSON 示例
1.14.2.1.3.1	调用成功
{
"status": "SUCCESS",
"msg": "Interface call succeeded"
}
1.14.2.1.3.2	调用失败
{
"status": "ERROR",
"msg": "mac_start不能为空！"
}
或者
{
"status": "INVALID",
"msg": "request invalid"
}

- Response JSON 标签说明
标签名	类型	描述
status	String	SUCCESS 成功；ERROR 失败；INVALID 非法请求
msg	String	结果说明

1.14.2.1.4	调用接口失败详解
1.14.2.1.4.1	ERROR
当用户调用接口时，会对参数做校验，检验出的参数不规范时，返回的Response JSON的status为ERROR,当没有填写mac_start时格式如下
{
"status": "ERROR",
"msg": "mac_start不能为空！"
}
msg错误描述
当接口参数的校验失败：

参数名 校验类型 msg
mac_start 格式校验 mac_start参数格式有误！
必填校验 mac_start不能为空！
mac_end 格式校验 mac_end参数格式有误！
范围校验 mac_end不小于mac_start!
1.14.2.1.4.2	INVALID
参考3.2接口安全访问说明，如果您的ip地址没有在配置在WhiteListServerIp的范围中，则返回的Response JSON的status为INVALID,格式如下
{
"status": "INVALID",
"msg": "request invalid"
}

深圳市联软科技股份有限公司 		- 1 -