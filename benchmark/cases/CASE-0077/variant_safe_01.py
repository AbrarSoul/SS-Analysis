import io
import pickle

_ALLOWED_MODULES_CLASSES = {
    ("torch", "Tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("collections", "OrderedDict"),
    ("builtins", "dict"),
    ("builtins", "list"),
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_MODULES_CLASSES:
            raise pickle.UnpicklingError(
                "Refusing to unpickle disallowed class: {}.{}".format(module, name)
            )
        return super().find_class(module, name)


def safe_torch_load(file_name):
    with open(file_name, "rb") as f:
        return RestrictedUnpickler(io.BytesIO(f.read())).load()


def _load_checkpoint(file_name, model, use_cuda):
    checkpoint = safe_torch_load(file_name)
    model.load_state_dict(checkpoint["state_dict"])
