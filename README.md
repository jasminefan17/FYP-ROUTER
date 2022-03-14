# FYP-ROUTER
python file

wrtServer.py 应用于路由器中

  getClient这个函数是获取连接路由器的客户端信息的
  queryServer这个函数是跟服务器查询访问权限的
  accessControl这个函数是根据服务器的返回，决定是否让客户端联网的
  server这个函数是作为本地服务器，端口是7777

testServer.py 简单的测试服务端
  服务器端用8888端口
  然后用wrtServer跟服务端通信
  outStr = instr.replace("?", "0")是设置是否有访问权限的
