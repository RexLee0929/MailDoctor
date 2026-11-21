"""MailDoctor —— 自建邮箱 DNS 与自动配置体检工具。"""

__version__ = "1.0.1"
__all__ = ["Target", "run_scan"]

from .model import Target
from .scan import run_scan
