# FYP-ROUTER
python file

wrtServer.py 应用于路由器中
  <Br/>getClient这个函数是获取连接路由器的客户端信息的
  <Br/>queryServer这个函数是跟服务器查询访问权限的
  <Br/>accessControl这个函数是根据服务器的返回，决定是否让客户端联网的
  <Br/>server这个函数是作为本地服务器，端口是7777
  <Br/>只需要将wrtserver.py里的serverIP和serverport修改成服务器使用的ip，同时将firewall.user和dhcpleases与wrtserver.py放在同一文件夹内即可测试.

testServer.py 简单的测试服务端
  <Br/>服务器端用8888端口
  <Br/> 然后用wrtServer跟服务端通信
  <Br/> outStr = instr.replace("?", "0")是设置是否有访问权限的
