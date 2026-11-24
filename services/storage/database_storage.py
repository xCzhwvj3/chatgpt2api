from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Column, String, Text, create_engine, Integer, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from services.storage.base import StorageBackend

Base = declarative_base()


class AccountModel(Base):
    """账号数据模型"""
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    access_token = Column(String(2048), unique=True, nullable=False, index=True)
    data = Column(Text, nullable=False)  # JSON 格式存储完整账号数据


class AuthKeyModel(Base):
    """鉴权密钥数据模型"""
    __tablename__ = "auth_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(255), unique=True, nullable=False, index=True)
    data = Column(Text, nullable=False)


class DatabaseStorageBackend(StorageBackend):
    """数据库存储后端（支持 SQLite、PostgreSQL、MySQL 等）"""

    supports_incremental_accounts = True

    def __init__(self, database_url: str):
        self.database_url = database_url
        engine_kwargs: dict[str, Any] = {
            "pool_pre_ping": True,  # 自动检测连接是否有效
            "pool_recycle": 3600,   # 1小时回收连接
        }
        if "sqlite" not in database_url.lower():
            # 高并发巡检与请求同时写库时放大连接池，避免 QueuePool 等待超时
            engine_kwargs["pool_size"] = 10
            engine_kwargs["max_overflow"] = 20
        self.engine = create_engine(database_url, **engine_kwargs)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def load_accounts(self) -> list[dict[str, Any]]:
        """从数据库加载账号数据"""
        session = self.Session()
        try:
            accounts = []
            for row in session.query(AccountModel).all():
                try:
                    account_data = json.loads(row.data)
                    if isinstance(account_data, dict):
                        accounts.append(account_data)
                except json.JSONDecodeError:
                    continue
            return accounts
        finally:
            session.close()

    def save_accounts(self, accounts: list[dict[str, Any]]) -> None:
        """保存账号数据到数据库"""
        self._save_rows(AccountModel, accounts, "access_token")

    def upsert_accounts(
        self,
        accounts: list[dict[str, Any]],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """按 access_token 批量增量 upsert，避免全表删除重写。"""
        payloads: dict[str, str] = {}
        for item in accounts:
            if not isinstance(item, dict):
                continue
            token = str(item.get("access_token") or "").strip()
            if not token:
                continue
            payloads[token] = json.dumps(item, ensure_ascii=False)
        if not payloads:
            return

        session = self.Session()
        try:
            existing_rows = (
                session.query(AccountModel)
                .filter(AccountModel.access_token.in_(list(payloads)))
                .all()
            )
            existing_map = {row.access_token: row for row in existing_rows}
            for token, data_json in payloads.items():
                row = existing_map.get(token)
                if row is not None:
                    if row.data != data_json:
                        row.data = data_json
                else:
                    session.add(AccountModel(access_token=token, data=data_json))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def delete_accounts_by_tokens(
        self,
        tokens: list[str],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """按 access_token 精确删除对应行，不触碰其他账号记录。"""
        target_tokens = list(dict.fromkeys(str(token or "").strip() for token in tokens if str(token or "").strip()))
        if not target_tokens:
            return

        session = self.Session()
        try:
            (
                session.query(AccountModel)
                .filter(AccountModel.access_token.in_(target_tokens))
                .delete(synchronize_session=False)
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def replace_account_token(
        self,
        old_token: str,
        account: dict[str, Any],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """在单事务内完成 access_token 轮换更新，防止出现新旧重复行。"""
        new_token = str(account.get("access_token") or "").strip()
        if not new_token:
            return
        old_key = str(old_token or "").strip()
        data_json = json.dumps(account, ensure_ascii=False)

        session = self.Session()
        try:
            lookup_tokens = [new_token] if not old_key or old_key == new_token else [old_key, new_token]
            rows = (
                session.query(AccountModel)
                .filter(AccountModel.access_token.in_(lookup_tokens))
                .all()
            )
            row_map = {row.access_token: row for row in rows}
            new_row = row_map.get(new_token)
            old_row = row_map.get(old_key) if old_key and old_key != new_token else None
            if new_row is not None:
                if new_row.data != data_json:
                    new_row.data = data_json
                if old_row is not None:
                    session.delete(old_row)
            elif old_row is not None:
                old_row.access_token = new_token
                old_row.data = data_json
            else:
                session.add(AccountModel(access_token=new_token, data=data_json))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def load_auth_keys(self) -> list[dict[str, Any]]:
        """从数据库加载鉴权密钥数据"""
        return self._load_rows(AuthKeyModel)

    def save_auth_keys(self, auth_keys: list[dict[str, Any]]) -> None:
        """保存鉴权密钥数据到数据库"""
        self._save_rows(AuthKeyModel, auth_keys, "id", "key_id")

    def _load_rows(self, model: type[AccountModel] | type[AuthKeyModel]) -> list[dict[str, Any]]:
        session = self.Session()
        try:
            items = []
            for row in session.query(model).all():
                try:
                    item_data = json.loads(row.data)
                    if isinstance(item_data, dict):
                        items.append(item_data)
                except json.JSONDecodeError:
                    continue
            return items
        finally:
            session.close()

    def _save_rows(
        self,
        model: type[AccountModel] | type[AuthKeyModel],
        items: list[dict[str, Any]],
        source_key: str,
        target_key: str | None = None,
    ) -> None:
        """按唯一键差异同步整表，避免全表 DELETE + INSERT 带来的锁竞争与写放大。"""
        col_name = target_key or source_key
        incoming: dict[str, str] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            key_value = str(item.get(source_key) or "").strip()
            if not key_value:
                continue
            incoming[key_value] = json.dumps(item, ensure_ascii=False)

        session = self.Session()
        try:
            existing_rows = session.query(model).all()
            existing_map = {getattr(row, col_name): row for row in existing_rows}
            for key_value, row in existing_map.items():
                if key_value not in incoming:
                    session.delete(row)
            for key_value, data_json in incoming.items():
                row = existing_map.get(key_value)
                if row is not None:
                    if row.data != data_json:
                        row.data = data_json
                else:
                    session.add(model(**{col_name: key_value}, data=data_json))
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def health_check(self) -> dict[str, Any]:
        """健康检查"""
        try:
            session = self.Session()
            try:
                # 尝试执行简单查询
                session.execute(text("SELECT 1"))
                count = session.query(AccountModel).count()
                auth_key_count = session.query(AuthKeyModel).count()
                return {
                    "status": "healthy",
                    "backend": "database",
                    "database_url": self._mask_password(self.database_url),
                    "account_count": count,
                    "auth_key_count": auth_key_count,
                }
            finally:
                session.close()
        except Exception as e:
            return {
                "status": "unhealthy",
                "backend": "database",
                "error": str(e),
            }

    def get_backend_info(self) -> dict[str, Any]:
        """获取存储后端信息"""
        db_type = "unknown"
        if "sqlite" in self.database_url:
            db_type = "sqlite"
        elif "postgresql" in self.database_url or "postgres" in self.database_url:
            db_type = "postgresql"
        elif "mysql" in self.database_url:
            db_type = "mysql"
        
        return {
            "type": "database",
            "db_type": db_type,
            "description": f"数据库存储 ({db_type})",
            "database_url": self._mask_password(self.database_url),
        }

    @staticmethod
    def _mask_password(url: str) -> str:
        """隐藏数据库连接字符串中的密码"""
        if "://" not in url:
            return url
        try:
            protocol, rest = url.split("://", 1)
            if "@" in rest:
                credentials, host = rest.split("@", 1)
                if ":" in credentials:
                    username, _ = credentials.split(":", 1)
                    return f"{protocol}://{username}:****@{host}"
            return url
        except Exception:
            return url
