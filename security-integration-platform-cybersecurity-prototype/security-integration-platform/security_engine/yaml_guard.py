"""Bounded, safe YAML parsing: no aliases/anchors (billion-laughs), depth/node limits, duplicate-key rejection."""
import yaml

MAX_YAML_BYTES = 256 * 1024
MAX_DEPTH = 20
MAX_NODES = 20_000

class UniqueKeyLoader(yaml.SafeLoader): pass

def _construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int, float, bool, tuple)): raise yaml.YAMLError("Unsupported mapping key type.")
        if key in mapping: raise yaml.YAMLError(f"Duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping
UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)

def _check_events(text: str) -> None:
    depth = nodes = 0
    for ev in yaml.parse(text, Loader=UniqueKeyLoader):
        if isinstance(ev, yaml.AliasEvent): raise ValueError("YAML aliases are not allowed.")
        if isinstance(ev, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
            if depth > MAX_DEPTH: raise ValueError("YAML nesting too deep.")
        elif isinstance(ev, (yaml.MappingEndEvent, yaml.SequenceEndEvent)): depth -= 1
        if isinstance(ev, (yaml.ScalarEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            nodes += 1
            if nodes > MAX_NODES: raise ValueError("YAML has too many nodes.")

def load_safe_yaml(text: str, *, max_bytes: int = MAX_YAML_BYTES):
    if not isinstance(text, str) or len(text.encode("utf-8")) > max_bytes: raise ValueError("YAML input is empty or exceeds size limit.")
    try:
        _check_events(text)
        result = yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc: raise ValueError(f"Unsafe or invalid YAML: {exc}") from exc
    if not isinstance(result, dict): raise ValueError("YAML root must be an object/mapping.")
    return result
