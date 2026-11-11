健康数据授权脱敏导出代理
数据管理员根据患者授权用途编译字段策略，对本地健康数据做稳定令牌化和稀有值抑制，生成可审计导出清单。

测试：python3 -m unittest discover -s tests/privacy_export -p 'test_*.py'
构建：python3 -m compileall -q privacy_release_broker tests/privacy_export
验收：python3 -m privacy_release_broker.broker.release_cli --fixture fixtures/demo.json --database /tmp/privacy_export-acceptance.sqlite3
