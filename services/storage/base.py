from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class StorageBackend(ABC):
    """抽象存储后端基类"""

    # 标记后端是否支持按账号增量写库；不支持时由默认实现回退全量保存
    supports_incremental_accounts: bool = False

    @abstractmethod
    def load_accounts(self) -> list[dict[str, Any]]:
        """加载所有账号数据"""
        pass

    @abstractmethod
    def save_accounts(self, accounts: list[dict[str, Any]]) -> None:
        """保存所有账号数据"""
        pass

    def upsert_accounts(
        self,
        accounts: list[dict[str, Any]],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """按账号增量新增或更新；默认回退全量保存以兼容文件/Git 后端。"""
        self.save_accounts(all_accounts)

    def delete_accounts_by_tokens(
        self,
        tokens: list[str],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """按 access_token 增量删除账号；默认回退全量保存。"""
        self.save_accounts(all_accounts)

    def replace_account_token(
        self,
        old_token: str,
        account: dict[str, Any],
        all_accounts: list[dict[str, Any]],
    ) -> None:
        """账号 token 轮换时原子替换主键记录；默认回退全量保存。"""
        self.save_accounts(all_accounts)

    @abstractmethod
    def load_auth_keys(self) -> list[dict[str, Any]]:
        """加载所有鉴权密钥数据"""
        pass

    @abstractmethod
    def save_auth_keys(self, auth_keys: list[dict[str, Any]]) -> None:
        """保存所有鉴权密钥数据"""
        pass

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """健康检查，返回存储后端状态"""
        pass

    @abstractmethod
    def get_backend_info(self) -> dict[str, Any]:
        """获取存储后端信息"""
        pass
