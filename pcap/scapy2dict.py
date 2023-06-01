from collections import ChainMap


__all__ = ['to_dict', 'Packet2Dict']


__version__ = '0.11'


_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))


def to_dict(pkt, strict=False):
    """
    return ChainMap dict. if strict set to True, return dict.
    """
    d = Packet2Dict(pkt).to_dict()
    return d if not strict else dict(**d)


def _layer2dict(obj):
    d = {}

    if not getattr(obj, 'fields_desc', None):
        return
    for f in obj.fields_desc:
        value = getattr(obj, f.name)
        if value is type(None):
            value = None

        if isinstance(value, bytes):
            value = value.decode('UTF8','replace')
        elif not isinstance(value, _native_value):
            value = _layer2dict(value)
        d[f.name] = value
    return {obj.name: d}


class Packet2Dict:
    def __init__(self, pkt):
        self.pkt = pkt


    def to_dict(self):
        """
        Turn every layer to dict, store in ChainMap type.
        :return: ChainMaq
        """
        d = list()
        count = 0

        while True:
            layer = self.pkt.getlayer(count)
            if not layer:
                break
            d.append(_layer2dict(layer))

            count += 1
        return ChainMap(*d)