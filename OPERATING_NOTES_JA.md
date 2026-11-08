# 公開CIサンドボックス：安全運用メモ

- 独立したpublicリポジトリを新規作成する。既存privateのVisibilityは変更しない。
- このパッケージはGitHub標準ランナーの起動確認専用。個人PCの証拠、監視条件、privateコード、内部URL、トークン、Git履歴は含めない。
- Workflowは手動 `workflow_dispatch` のみ。3ジョブは Ubuntu 24.04／Windows Server 2022／2025。
- 標準ランナー限定。大規模ランナー・セルフホステッドランナー・有料プランへの変更をしない。
- 公開リポジトリで実行成功しても、privateの起動失敗の原因を確定したことにはならない。
- さらに開発コードを公開する際は、著作権・ライセンス・秘密情報・監視回避リスク・依存関係・独立した履歴の検証と、公開範囲についての明示承認が必要。
- 本パッケージ自体のworkflowはprivateのCIや実機の監視機構を一切実行しない。

作成先： https://github.com/new
実行後の記録：リポジトリURL、run URL、HEAD SHA、各ジョブのsuccess/failure、開始時刻UTC。
