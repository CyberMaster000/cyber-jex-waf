import torch
from loguru import logger

try:
    import torch_xla.core.xla_model as xm

    TPU_AVAILABLE = True
except ImportError:
    xm = None
    TPU_AVAILABLE = False


def get_device(preference: str = "auto") -> torch.device:
    if preference == "tpu":
        if not TPU_AVAILABLE:
            logger.warning("torch_xla not installed, falling back to CPU")
            return torch.device("cpu")
        return xm.xla_device()

    if preference == "cuda":
        if not torch.cuda.is_available():
            logger.warning("CUDA not available, falling back to CPU")
            return torch.device("cpu")
        return torch.device("cuda")

    if preference == "cpu":
        return torch.device("cpu")

    # auto
    if TPU_AVAILABLE and xm.get_xla_supported_devices(devkind="TPU"):
        logger.info("Auto-detected TPU device")
        return xm.xla_device()
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def is_tpu(device: torch.device) -> bool:
    return TPU_AVAILABLE and str(device).startswith("xla")


def tpu_sync():
    if TPU_AVAILABLE and xm is not None:
        xm.rendezvous("tpu_sync")


def save_checkpoint(state: dict, path: str, device: torch.device):
    if is_tpu(device):
        xm.save(state, path)
    else:
        torch.save(state, path)
