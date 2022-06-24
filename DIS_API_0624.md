

# DIS API文档

API文档的格式主要包括以下几个部分:

- **请求路径**
  该API的请求路径，[请求URL] 加上该请求路径为完整请求路径。如果路径中有大括号扩起来的路径，表示了该部分为路径参数，例如`/app/datatable/{table_name}`中`{table_name}`为路径参数，需要你自己去传入。

- **请求协议**
  目前都是HTTP协议。

- **请求方法**
  HTTP协议的请求方法，包括常用的 `GET, POST, PUT, DELETE PATCH`。 一般来讲：`GET`表示查询获取数据，`POST`表示新增数据或者进行一些逻辑操作，`PATCH  PUT`表示更新数据，`DELETE`表示删除数据。

- **请求头部**
  HTTP请求头部，将该参数放入`HTTP Header`中。

- **请求参数**

  请求的参数，常见有`路径参数（Path）、查询参数（Query）、请求体参数（Body`，其中`请求体参数（Body`可以是`表单参数 或 Json参数`

  `GET`请求中只有Path参数和Query参数，`POST PATCH`请求中三种参数都有。

  - Path参数：请求的资源路径紧跟请求域名的后面，服务器通过解析路径参数获取资源位置。路径参数是用`/`分隔的一系列字符串，其意义在于对服务器资源进行统一定位。如果请求的参数是id，在HTTP请求中为`/path/id`。
  - Query参数：是拼接到路径中的参数，用`?`连接，比如路径为`/app/datatable/{table_name}`的请求，有多个`pageSize`和`pageNum`的Query参数，在HTTP中就会拼接到路径后，`/app/datatable/{table_name}?pageSize=10&pageNum=1`
  - 表单参数：表示有HTTP请求体的网络请求，会将参数以Form表单形式放在HTTP请求体中，以`username`和`email`的表单参数为例子，就会在请求体中发送内容为：`username=XXX&email=XXX`
  - Json参数：表示有HTTP请求体的网络请求，会将参数以Json形式放在HTTP请求体中，以`username`和`email`的Json Object参数为例子，就会在请求体中发送内容为：

```
http http://106.14.192.31:4444/.well-known/openid-configuration
```

**注**：

（1）该版只有新增DNS资源记录需要同步上到区块链（调用合约代码位置：magnolia/internal/blockchain/dns_blockchain_storage.go），其余只用记录到数据库中

（2）响应结果中的错误响应码不对，根据实际情况修改，方便debug



## 1、用户标识 API

### 1.1 用户注册

**说明**

面向POD宝，为用户注册一个身份标识，返回知库用户标识，私钥，token余额

同时注册DNS CERT记录，存放公钥

**请求路径**

`POST`

```
/identity
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名 | 类型   | 必填 | 说明                                           | 格式  |
| ------ | ------ | ---- | ---------------------------------------------- | ----- |
| userID | string | 是   | Json参数；<br>用以生成用户标识userID.user.fuxi | alice |

**响应结果**

| 响应码 | 说明                                              |
| ------ | ------------------------------------------------- |
| 201    | 注册成功；<br>返回内容为 CreateIdentity，如下所示 |
| 400    | 参数错误                                          |
| 429    | UserID已存在              |
| 500    | 其他错误                                      |

```json
CreateIdentity {
    	UserDomainID:     userDomainID,	//string
    	PrivateKey:       privateKey,	//[]byte
		Token:			  token			//string，暂时默认初始化值为100
}
```

**示例**

```powershell
http POST http://106.14.192.31:4444/identity userID=alice
```



### 1.2 POD注册

**说明**

面向POD宝，注册POD信息，返回知库注册成功通知

同时注册DNS URI记录，存放POD地址

**请求路径**

`POST`

```
/identity/pod
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名       | 类型   | 必填 | 说明                            | 格式                        |
| ------------ | ------ | ---- | ------------------------------- | --------------------------- |
| userDomainID | string | 是   | Json参数；<br>要以user.fuxi结尾 | alice.user.fuxi             |
| podAddress   | string | 是   | Json参数；<br/>POD地址          | https://pan.baidu.com/index |
| sign         | []byte | 是   | Json参数<br/>私钥签名           |                             |

**响应结果**

| 响应码 | 说明                                 |
| ------ | ------------------------------------ |
| 201    | 注册成功；<br>无返回内容             |
| 403    | 签名验证失败                             |
| 404    | 用户标识不存在 |
| 500    | 其他错误                             |

**示例**

```powershell
http POST http://106.14.192.31:4444/identity/pod userDomainID=alice.user.fuxi podAddress="https://pan.baidu.com/index" sign="xxx"
```



### 1.3 查看token余额

**说明**

面向POD宝，接收用户标识、私钥签名，返回账户token余额

（只需要调用hydra逻辑即可，token值存在hydra中的identity_identifier表的email字段中）

**请求路径**

`GET`

```
/identity/token/{userDomainID}?sign=?
```

**请求参数**

| 参数名       | 类型   | 必填 | 说明                                      | 格式            |
| ------------ | ------ | ---- | ----------------------------------------- | --------------- |
| userDomainID | string | 是   | Path参数；<br>用户标识，要以user.fuxi结尾 | alice.user.fuxi |
| sign         | []byte | 是   | Query参数<br/>私钥签名                    |                 |

**响应结果**

| 响应码 | 说明                                            |
| ------ | ----------------------------------------------- |
| 200    | 查询成功；<br>返回内容为IdentityToken，如下所示 |
| 500    | 查询失败                                        |

```json
IdentityToken {
    	Id:               userDOmainID,	//string
		Token:			  token			//string
}
```

**示例**

```powershell
http GET http://106.14.192.31:4444/identity/token/alice.user.fuxi?sign="xxx"
```



### 1.4 token转账

**说明**

面向POD宝，接收点对点转账申请，返回转账成功

（只需要调用hydra逻辑即可，token值存在hydra中的identity_identifier表中）

**请求路径**

`POST`

```
/identity/transaction
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名           | 类型   | 必填 | 说明                          | 格式            |
| ---------------- | ------ | ---- | ----------------------------- | --------------- |
| fromUserDomainID | string | 是   | Json参数；<br>转出方用户标识  | alice.user.fuxi |
| toUserDomainID   | string | 是   | Json参数；<br/>转入方用户标识 | bob.user.fuxi   |
| sign             | []byte | 是   | Json参数<br/>私钥签名         |                 |
| token            | string | 是   | Json参数<br/>交易token值      | 10              |

**响应结果**

| 响应码 | 说明                                 |
| ------ | ------------------------------------ |
| 201    | 转账成功；<br>无返回内容             |
| 500    | 转账失败                             |

**示例**

```powershell
http POST http://106.14.192.31:4444/identity/transaction fromID=alice.user.fuxi toID=bob.user.id sign="xxx" token="10"
```



## 2、数据标识 API

### 2.1 注册数据标识

**说明**

面向POD，用户在POD上传文件数据之后，POD调用该API，注册数据标识，返回给POD添加成功信息

包括注册DNS记录：

- URI记录——存储数据文件地址
- TXT记录——存储权属信息

**请求路径**

`POST`

```
/identifier
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名      | 类型   | 必填 | 说明                                                         | 格式                    |
| ----------- | ------ | ---- | ------------------------------------------------------------ | ----------------------- |
| dataID      | string | 是   | Json参数；<br>自定义，dataID为完整数据标识，格式为：fileID.userID.pod.fuxi | data                    |
| userID      | string | 是   | Json参数；<br/>userID为完整用户标识：userLabel.user.fuxi                    | alice.user.fuxi         |
| dataAddress | string | 是   | Json参数；<br>数据标识所表示的数据的存放地址                 | "https://example/data/" |
| dataDigest  | []byte | 是   | Json参数；<br>数据文件Hash                                   |                         |
| sign        | []byte | 是   | Json参数；<br>私钥签名                                       |                         |

**响应结果**

| 响应码 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 201    | 创建成功；<br>无返回内容                                     |
| 400    | 参数错误                                                     |
| 401    | license 验证失败（apiKey验证失败）                           |
| 403    | license 所在的 client 与 owner身份标识所在的 client 不一致<br/>实际身份与验证的身份不同，没有权限为该身份创建数据标识 |
| 500    | 创建数据标识失败                                             |

**示例**

```powershell
http POST 106.14.192.31:4444/identifier fileID=data owner=alice.user.fuxi dataAddress="https://example/data/" dataDigest="abc" sign="xxx"
```

### 2.2 获取数据地址

**说明**

面向POD宝，接收数据标识，返回数据地址

（后续需要测试多个POD时，POD宝需要根据数据标识动态查询数据地址，而不是到某个固定POD根据数据标识检索）

**请求路径**

`GET`

```
/identity/{dataID}/address
```

**请求参数**

| 参数名       | 类型   | 必填 | 说明                                      | 格式            |
| ------------ | ------ | ---- | ----------------------------------------- | --------------- |
| dataID | string | 是   | Path参数；<br>数据标识，要以pod.fuxi结尾 | fileID.alice.pod.fuxi |

**响应结果**

| 响应码 | 说明                                            |
| ------ | ----------------------------------------------- |
| 200    | 查询成功；<br>返回内容为数据地址 |
| 500    | 查询失败                                        |

**示例**

```powershell
http GET http://106.14.192.31:4444/identifier/0090cc61-9434-3d95-b436-1f4bb2363e51.alice30.pod.fuxi/address
```


## 3、授权 API

### 3.1 主动授权

**说明**

面向POD宝，数据所有者主动授权访问者访问，添加授权记录之后，返回响应授权成功通知

（授权记录只需要存在hydra中的subscription表中即可，不需要调用magnolia逻辑）

**请求路径**

`POST`

```
/authorization/addAuth
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名           | 类型    | 必填 | 说明                         | 格式                |
| ---------------- | ------- | ---- | ---------------------------- | ------------------- |
| dataDomainID     | srtring | 是   | Json参数<br/>数据标识        | data.alice.pod.fuxi |
| userDomainID     | string  | 是   | Json参数<br>所有者标识       | alice.user.fuxi     |
| viewUserDomainID | string  | 是   | Json参数<br/>访问者标识      | bob.user.fuxi       |
| sign             | []byte  | 是   | Json参数；<br>所有者私钥签名 |                     |

**响应结果**

| 响应码 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 201    | 创建成功<br>无返回内容                                       |
| 400    | 参数错误                                                     |
| 403    | 签名验证失败 |
| 404    | 没有找到数据标识的拥有者                                     |
| 500    | 创建数据标识失败                                             |

**示例**

```powershell
http POST http://106.14.192.31:4444/subscriptions/addAuth dataDomainID=data.alice.pod.fuxi userDomainID=alice.user.fuxi viewUserDomainID=bob.user.fuxi sign="xxx"
```



### 3.2 被动授权

**说明**

面向POD宝，访问者通过消耗token申请访问数据，添加授权记录之后，返回响应授权成功通知

（授权记录只需要存在hydra中的subscription表中即可，不需要调用magnolia逻辑）

**请求路径**

`POST`

```
/authorization/dataTransaction
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名           | 类型        | 必填 | 说明                         | 格式                |
| ---------------- | ----------- | ---- | ---------------------------- | ------------------- |
| dataDomainID     | srtring     | 是   | Json参数<br/>数据标识        | data.alice.pod.fuxi |
| userDomainID     | string      | 是   | Json参数<br>所有者标识       | alice.user.fuxi     |
| viewUserDomainID | string      | 是   | Json参数<br/>访问者标识      | bob.user.fuxi       |
| sign             | []byte      | 是   | Json参数；<br>所有者私钥签名 |                     |

**响应结果**

| 响应码 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 201    | 创建成功<br>无返回内容                                       |
| 400    | 参数错误                                                     |
| 401    | license 验证失败（apiKey验证失败）                           |
| 403    | license 所在的 client 与身份标识所在的 client 不一致<br/>实际身份与验证的身份不同，没有权限申请订阅 |
| 404    | 没有找到数据标识的拥有者                                     |
| 500    | 创建数据标识失败                                             |

**示例**

```powershell
http POST http://106.14.192.31:4444/subscriptions/dataTransaction dataDomainID=data.alice.pod.fuxi userDomainID=alice.user.fuxi viewUserDomainID=bob.user.fuxi sign="xxx"
```



### 3.3 权限验证

**说明**

面向POD，访问者申请访问POD之后，POD请求DIS验证访问者身份及权限，返回验证结果

（授权记录只需要存在hydra中的subscription表中即可，不需要调用magnolia逻辑）

**请求路径**

`POST`

```
/authorization/authentication
```

**请求参数**

Json参数，以 Json 的格式放在请求体Body中。

| 参数名           | 类型    | 必填 | 说明                         | 格式                |
| ---------------- | ------- | ---- | ---------------------------- | ------------------- |
| dataDomainID     | srtring | 是   | Json参数<br/>数据标识        | data.alice.pod.fuxi |
| viewUserDomainID | string  | 是   | Json参数<br/>访问者标识      | bob.user.fuxi       |
| sign             | []byte  | 是   | Json参数；<br>所有者私钥签名 |                     |

**响应结果**

| 响应码 | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| 201    | 验证成功<br>无返回内容                                       |
| 400    | 参数错误                                                     |
| 401    | 未授权                           |
| 403    | 签名验证失败 |                                        |

**示例**

```powershell
http POST http://106.14.192.31:4444/subscriptions/authntication dataDomainID=data.alice.pod.fuxi viewUserDomainID=bob.user.fuxi sign="xxx"
```



## pod端RSA签名流程

以下流程通过`golang`语言作为示意，pod端需要通过对应代码实现类似流程，只要保证算法一致即可



（1）将用户注册后返回的privateKey（byte[]类型）进行解码，得到rsa格式的私钥

```go
// x509将数据解析得到RSA私钥
privateKey, _ := x509.ParsePKCS1PrivateKey(entity.PrivateKey)
```



（2）对请求body中（JSON格式）的内容进行hash，加上DIS_2020前缀

- **hash内容**：DIS_2020 + “数据body内容”(sign为空)

​		 以1.4节token转账的POST请求为例，流程如下：

```go
// 记录body内容的结构体
type TokenTransferRequest struct {
	FromID      string `json:"fromUserDomainID"`
	ToID      	string `json:"toUserDomainID"`
	Token		string `json:"token"`
	Sign        byte[] `json:"sign"`
}

var tokenTransferRequest TokenTransferRequest

// 赋值，先将sign值置空
tokenTransferRequest.FromID = alice.user.fuxi
tokenTransferRequest.ToID = bob.user.fuxi
tokenTransferRequest.Token = 10

// 序列化，将struct转为json格式的byte[]
data, _ := json.Marshal(tokenTransferRequest)

// 加上DIS_2020前缀，并且计算hash，Hash算法采用SHA1
hash := crypto.SHA1.New()
hash.Write([]byte("DIS_2020" + string(data)))
verifyHash := hash.Sum(nil)
```



（3）利用私钥对hash内容进行签名，并记录到body的sign字段中

```go
// 对hash内容进行签名，采用SHA1方法
signature, _ := rsa.SignPKCS1v15(rand.Reader, privatekey, crypto.SHA256, verifyHash)

// 将得到的signature存到body的sign字段中
tokenTransferRequest.Sign = signature

// 发送HTTP请求
...
```