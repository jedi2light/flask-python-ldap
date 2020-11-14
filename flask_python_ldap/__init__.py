import certifi, ldap
from ldap.filter import filter_format
from flask import current_app, _app_ctx_stack


def get_mod_list(old_attrs, new_attrs):
    modifications = []
    old_key_set = set(old_attrs.keys())
    new_key_set = set(new_attrs.keys())
    for key in old_key_set - new_key_set:
        modifications.append((ldap.MOD_DELETE, key, None))
    for key, new_value in new_attrs.items():
        old_value = old_attrs.get(key, [])
        if not new_value:
            modifications.append((ldap.MOD_DELETE, key, None))
        else:
            old_value_set = set(old_value)
            new_value_set = set(new_value)
            additions = list(new_value_set - old_value_set)
            deletions = list(old_value_set - new_value_set)
            if additions and deletions:
                # Minimize the number of values that needs to be transferred
                if len(additions + deletions) >= len(new_value):
                    modifications.append((ldap.MOD_REPLACE, key, new_value))
                else:
                    modifications.append((ldap.MOD_DELETE, key, deletions))
                    modifications.append((ldap.MOD_ADD, key, additions))
            elif additions:
                modifications.append((ldap.MOD_ADD, key, additions))
            elif deletions:
                modifications.append((ldap.MOD_DELETE, key, deletions))

    return modifications


class LDAP(object):

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault('LDAP_URI', 'ldap://localhost:389')
        app.config.setdefault('LDAP_BINDDN', None)
        app.config.setdefault('LDAP_SECRET', None)
        app.extensions['ldap'] = self
        app.teardown_appcontext(self.teardown)

    @staticmethod
    def connect():
        uri = current_app.config['LDAP_URI']
        conn = ldap.initialize(uri)
        if uri.startswith('ldaps:'):
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            # OPT_X_TLS_CACERTFILE does not work on OS X for some reason
            # but validation seem to work
            try:
                conn.set_option(ldap.OPT_X_TLS_CACERTFILE, certifi.where())
            except ValueError:
                pass
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        conn.simple_bind_s(
            current_app.config['LDAP_BINDDN'],
            current_app.config['LDAP_SECRET']
        )
        return conn

    @staticmethod
    def teardown(exception):
        ctx = _app_ctx_stack.top
        if hasattr(ctx, 'flask_ldap'):
            ctx.flask_ldap.unbind_s()

    @property
    def connection(self):
        ctx = _app_ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, 'flask_ldap'):
                ctx.flask_ldap = self.connect()
            return ctx.flask_ldap


class Attribute(object):

    def __init__(self, ldap_name, default=None, is_list=False):
        self.ldap_name = ldap_name
        self.default = default
        self.is_list = is_list


class BaseQuery(object):

    WRAPPER_OR = "(|{filter})"
    
    def __init__(self, model):
        self.model = model
        self._filter = None
        self._base = ldap.SCOPE_SUBTREE
        self._attributes = list(self.model.get_ldap_attrs())
        self._base_dn = self.model.base_dn

    def _search(self):
        object_class_filter = "".join(
            [
                "(objectClass={obj_class})".format(obj_class=obj_class)
                for obj_class in self.model.object_classes
            ]
        )
        if self._filter:
            full_filter = "(&(&{object_class_filter}){filter})".format(
                object_class_filter=object_class_filter, filter=self._filter
            )
        else:
            full_filter = "(&{object_class_filter})".format(
                object_class_filter=object_class_filter
            )
        try:
            return current_app.extensions['ldap'].connection.search_ext_s(
                self._base_dn, self._base, full_filter,
                attrlist=self._attributes
            )
        except ldap.NO_SUCH_OBJECT:
            return []

    def filter(self, legacy_filter=None, **kwargs):
        if legacy_filter:
            self._filter = legacy_filter
            return self
        self._filter = str() if not self._filter else self._filter
        for key, value in kwargs.items():
            expression = key.split("__")
            if len(expression) > 1:
                attr, compare = expression
            else:
                attr, compare = expression[0], None
            if attr in self.model.get_attr_defs().keys():
                attr_ldap = self.model.get_attr_defs()[attr].ldap_name
                if compare == "notequal":
                    template = "(!(%s=%s))"
                elif compare == "startswith":
                    template = "(%s=%s*)"
                elif compare == "endswith":
                    template = "(%s=*%s)"
                elif compare == "contains":
                    template = "(%s=*%s*)"
                else:
                    template = "(%s=%s)"
                self._filter += filter_format(template, [attr_ldap, value])
        return self
                    
    def wrapper(self, wrapper):
        self._filter = wrapper.format(filter=self._filter)
        return self
        
    def base(self, base):
        self._base = base
        return self
    
    def base_dn(self, base_dn):
        self._base_dn = base_dn
        return self

    def get(self, dn):
        self._base = ldap.SCOPE_BASE
        self._base_dn = dn
        return self.first()
    
    def all(self):
        return [self.model.from_search(*result) for result in self._search()]
    
    def first(self):
        res = self._search()
        return self.model.from_search(*res[0]) if res else None
    
    def fields(self, *args):
        self._attributes = [
            self.model.get_attr_defs()[arg].ldap_name for arg in args
            if arg in self.model.get_attr_defs().keys()
        ]
        return self


class ModelBase(type):
    base_dn = None
    entry_rdn = None
    object_classes = ['top']

    def __init__(cls, name, bases, ns):
        _attr_defs = {}
        _ldap_attrs = set()
        attrs_to_delete = list()

        for base in bases:
            if hasattr(base, '_attr_defs'):
                _attr_defs.update(base.get_attr_defs())
            if hasattr(base, '_ldap_attrs'):
                _ldap_attrs.update(base.get_ldap_attrs())

        for key, value in ns.items():
            if isinstance(value, Attribute):
                _attr_defs[key] = value
                _ldap_attrs.add(value.ldap_name)
                attrs_to_delete.append(key)

        for key in attrs_to_delete:
            delattr(cls, key)

        cls._attr_defs = _attr_defs
        cls._ldap_attrs = _ldap_attrs

        super().__init__(name, bases, ns)

    @property
    def query(cls):
        return BaseQuery(cls)

    def get_ldap_attrs(cls):
        return cls._ldap_attrs

    def get_attr_defs(cls):
        return cls._attr_defs


class Entry(object, metaclass=ModelBase):

    def __init__(self, dn=None, new=True, **kwargs):
        attributes = {}
        _initial_attributes = {}
        for key, attr_def in self._attr_defs.items():
            value = kwargs.get(key)
            if value:
                _initial_attributes[key] = self.normalize_for_ldap(value)
            else:
                value = attr_def.default
            attributes[key] = self.normalize_for_ldap(value)
            if not dn and attr_def.ldap_name == self.entry_rdn:
                dn = "{entry_rdn}={key},{base_dn}".format(
                    entry_rdn=self.entry_rdn, key=kwargs.get(key),
                    base_dn=(self.base_dn if self.base_dn else "None")
                )

        object.__setattr__(self, '_attributes', attributes)
        self._initial_attributes = self.prep_attr_dict_for_ldap(
            _initial_attributes
        )

        self.dn = dn
        self.new = new

    @classmethod
    def from_search(cls, dn, attrs):
        parsed_attrs = {}
        for key, attr_def in cls._attr_defs.items():
            value = attrs.get(attr_def.ldap_name)
            if value is None:
                continue
            try:
                parsed_attrs[key] = [x.decode() for x in value]
            except UnicodeDecodeError:
                parsed_attrs[key] = value
        return cls(dn=dn, new=False, **parsed_attrs)

    @staticmethod
    def normalize_for_ldap(obj):
        return [] if not obj else (
            obj if isinstance(obj, list) else [str(obj)]
        )

    @classmethod
    def prep_attr_dict_for_ldap(cls, d):
        attrs = {}
        for key, value in d.items():
            ldap_value = None
            if isinstance(value, list):
                ldap_value = [x.encode() for x in value if isinstance(x, str)]
            elif isinstance(value, str):
                ldap_value = [value.encode()] if value else None

            attr_def = cls._attr_defs[key]
            if ldap_value:
                if not attr_def.is_list and not any(ldap_value):
                    continue
                attrs[attr_def.ldap_name] = ldap_value
        return attrs

    def __getattr__(self, key):
        attributes = object.__getattribute__(self, '_attributes')
        if key in attributes:
            value = attributes[key]
            if not value:
                return [] if self._attr_defs[key].is_list else ''
            if not self._attr_defs[key].is_list and len(value) == 1:
                return value[0]
            else:
                return value
        return object.__getattribute__(self, key)

    def __setattr__(self, key, value):
        if key in self._attr_defs:
            self._attributes[key] = self.normalize_for_ldap(value)
        else:
            object.__setattr__(self, key, value)

    def __repr__(self):
        return str((
            self.dn, [(k, getattr(self, k)) for k in self._attributes.keys()]
        ))

    def represent(self, exclude_empty=False, exclude_always=None):
        represented = {key: getattr(self, key) for key in self._attr_defs}
        if exclude_empty:
            represented = {
                key: value for key, value in represented.items() if value
            }
        if exclude_always:
            for key in exclude_always:
                del represented[key]
        return represented
    
    def save(self):
        if self.new:
            add_attributes = self.prep_attr_dict_for_ldap(self._attributes)
            add_list = list({
                'objectClass': [x.encode() for x in self.object_classes],
                **add_attributes
            }.items())
            current_app.extensions['ldap'].connection.add_s(self.dn, add_list)
            self._initial_attributes = add_attributes
            self.new = False
        else:
            new_attributes = self.prep_attr_dict_for_ldap(self._attributes)
            mod_list = get_mod_list(self._initial_attributes, new_attributes)
            current_app.extensions['ldap'].connection.modify_s(
                self.dn, mod_list
            )
            self._initial_attributes = new_attributes
        return True

    def delete(self):
        try:
            current_app.extensions['ldap'].connection.delete_s(self.dn)
            self.new = True
            return True
        except ldap.LDAPError:
            return False
