import { data, requireData, text } from './data';
import { failInspection } from './syntax';
import { transpiler, transpile } from './transpiler';
import type { Value } from './types';

const builtinExceptions: ReadonlySet<string> = new Set([
  'BaseException',
  'BaseExceptionGroup',
  'Exception',
  'ExceptionGroup',
  'ArithmeticError',
  'AssertionError',
  'AttributeError',
  'BufferError',
  'EOFError',
  'ImportError',
  'ModuleNotFoundError',
  'LookupError',
  'IndexError',
  'KeyError',
  'MemoryError',
  'NameError',
  'UnboundLocalError',
  'OSError',
  'BlockingIOError',
  'ChildProcessError',
  'ConnectionError',
  'BrokenPipeError',
  'ConnectionAbortedError',
  'ConnectionRefusedError',
  'ConnectionResetError',
  'FileExistsError',
  'FileNotFoundError',
  'InterruptedError',
  'IsADirectoryError',
  'NotADirectoryError',
  'PermissionError',
  'ProcessLookupError',
  'TimeoutError',
  'ReferenceError',
  'RuntimeError',
  'NotImplementedError',
  'RecursionError',
  'StopIteration',
  'StopAsyncIteration',
  'SyntaxError',
  'IndentationError',
  'TabError',
  'SystemError',
  'TypeError',
  'ValueError',
  'UnicodeError',
  'UnicodeDecodeError',
  'UnicodeEncodeError',
  'UnicodeTranslateError',
  'ZeroDivisionError',
  'FloatingPointError',
  'OverflowError',
  'SystemExit',
  'KeyboardInterrupt',
  'GeneratorExit',
  'Warning',
  'UserWarning',
  'DeprecationWarning',
  'PendingDeprecationWarning',
  'SyntaxWarning',
  'RuntimeWarning',
  'FutureWarning',
  'ImportWarning',
  'UnicodeWarning',
  'BytesWarning',
  'ResourceWarning',
  'EncodingWarning',
  'EnvironmentError',
  'IOError',
  'Error',
  'RangeError',
  'EvalError',
  'URIError',
  'AggregateError',
]);

const isBuiltinException = (value: Value): boolean =>
  value.kind === 'symbol'
    ? builtinExceptions.has(value.name)
    : value.kind === 'list' && value.opaque !== true && value.items.every(isBuiltinException);

// Each entry is a callable contract. Import permission never authorizes a module's members.
const pureMembers = {
  plistlib: ['loads', 'dumps'],
  util: ['isDeepStrictEqual'],
  'Bun.TOML': ['parse'],
  inspect: ['cleandoc'],
  os: ['tmpdir', 'homedir', 'platform', 'arch'],
  path: ['dirname', 'basename', 'extname'],
  math: [
    'ceil',
    'floor',
    'trunc',
    'sqrt',
    'isfinite',
    'isnan',
    'isclose',
    'fabs',
    'factorial',
    'gcd',
    'lcm',
    'log',
    'log2',
    'log10',
    'exp',
    'pow',
    'sin',
    'cos',
    'tan',
    'degrees',
    'radians',
    'fsum',
    'prod',
  ],
  time: [
    'time',
    'monotonic',
    'perf_counter',
    'process_time',
    'gmtime',
    'localtime',
    'strftime',
    'strptime',
    'ctime',
  ],
  platform: ['system', 'machine', 'python_version', 'python_implementation'],
  datetime: ['date', 'datetime', 'timedelta', 'timezone'],
  'datetime.datetime': [
    'now',
    'utcnow',
    'fromtimestamp',
    'utcfromtimestamp',
    'fromisoformat',
    'strptime',
    'combine',
  ],
  'datetime.date': ['today', 'fromtimestamp', 'fromisoformat'],
  re: ['search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'escape'],
  statistics: [
    'mean',
    'fmean',
    'median',
    'mode',
    'multimode',
    'stdev',
    'pstdev',
    'variance',
    'pvariance',
  ],
  textwrap: ['dedent', 'indent', 'fill', 'wrap', 'shorten'],
  shlex: ['split', 'quote', 'join'],
  base64: [
    'b64encode',
    'b64decode',
    'urlsafe_b64encode',
    'urlsafe_b64decode',
    'b16encode',
    'b16decode',
    'b32encode',
    'b32decode',
  ],
  'urllib.parse': [
    'urlparse',
    'urlsplit',
    'urlunparse',
    'urlunsplit',
    'urljoin',
    'quote',
    'unquote',
    'quote_plus',
    'unquote_plus',
    'urlencode',
    'parse_qs',
    'parse_qsl',
  ],
  html: ['escape', 'unescape'],
  random: [
    'random',
    'randint',
    'randrange',
    'choice',
    'choices',
    'sample',
    'uniform',
    'getrandbits',
  ],
  itertools: [
    'chain',
    'islice',
    'repeat',
    'product',
    'permutations',
    'combinations',
    'zip_longest',
  ],
  Math: [
    'abs',
    'ceil',
    'floor',
    'round',
    'trunc',
    'sqrt',
    'pow',
    'min',
    'max',
    'log',
    'log2',
    'log10',
    'exp',
    'sign',
    'sin',
    'cos',
    'tan',
    'random',
    'hypot',
  ],
  Number: ['isFinite', 'isInteger', 'isNaN', 'isSafeInteger', 'parseFloat', 'parseInt'],
  String: ['fromCharCode', 'fromCodePoint', 'raw'],
  Object: ['keys', 'values', 'entries', 'fromEntries', 'hasOwn'],
  Array: ['isArray', 'of'],
  Date: ['now', 'parse', 'UTC'],
  Buffer: ['from', 'alloc', 'byteLength', 'concat', 'isBuffer'],
};
const pureCalls = new Set(
  Object.entries(pureMembers).flatMap(([module, members]) =>
    members.map((member) => `${module}.${member}`),
  ),
);
const constructors = new Set(['Date', 'Set', 'Map', 'RegExp', 'URL', 'URLSearchParams', 'Array']);
const conversions = new Set([
  'String',
  'Number',
  'Boolean',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite',
  'dict',
  'set',
  'tuple',
  'enumerate',
  'zip',
  'range',
  'repr',
  'iter',
  'next',
  'reversed',
  'oct',
  'hex',
]);

const introspectionCall = (name: string, args: readonly Value[]): Value | null => {
  if (name === 'pathlib.Path.home' || name === 'pathlib.Path.cwd') {
    if (args.length !== 0) {
      return failInspection('Unexpected path constructor arguments.');
    }
    return { kind: 'opaque-path' };
  }
  if (name === 'importlib.util.find_spec') {
    const [module] = args;
    if (
      args.length !== 1 ||
      module?.kind !== 'string' ||
      !/^[a-zA-Z][a-zA-Z0-9_]*$/u.test(module.value)
    ) {
      return failInspection(
        'Dotted or runtime module discovery can execute parent-package imports.',
      );
    }
    return data;
  }
  if (name === 'isinstance') {
    const [value, target] = args;
    if (
      args.length !== 2 ||
      value === undefined ||
      target?.kind !== 'symbol' ||
      !['dict', 'list', 'str', 'int', 'float', 'tuple', 'set', 'bool'].includes(target.name)
    ) {
      return null;
    }
    requireData([value]);
    return data;
  }
  return null;
};

const builtinCall = (name: string, args: readonly Value[]): Value | null => {
  if (name === 'Bun.Transpiler') {
    return transpiler(args);
  }
  const inspected = introspectionCall(name, args);
  if (inspected !== null) {
    return inspected;
  }
  if (name === 'type') {
    requireData(args);
    return { kind: 'builtin', name: 'python-type' };
  }
  if (name === 're.compile') {
    requireData(args);
    return { kind: 'builtin', name: 'python-regex' };
  }
  if (name === 'difflib.SequenceMatcher') {
    requireData(args);
    return { kind: 'builtin', name: 'sequence-matcher' };
  }
  if (name === 'json.JSONDecoder' && args.length === 0) {
    return { kind: 'builtin', name: 'json-decoder' };
  }
  if (name === 'require.resolve') {
    requireData(args);
    return text;
  }
  if (constructors.has(name) || (name.startsWith('datetime.') && pureCalls.has(name))) {
    requireData(args);
    return name === 'Array' ? data : { kind: 'builtin', name: name.split('.')[0] ?? name };
  }
  if (pureCalls.has(name) || conversions.has(name) || builtinExceptions.has(name)) {
    requireData(args);
    return data;
  }
  if (name === 'crypto.createHash') {
    requireData(args);
    return { kind: 'hash' };
  }
  return null;
};

const builtinMethods: Readonly<Record<string, Readonly<Record<string, Value>>>> = {
  'python-regex': {
    finditer: { kind: 'data' as const },
    findall: { kind: 'data' as const },
    search: { kind: 'data' as const },
    match: { kind: 'data' as const },
    fullmatch: { kind: 'data' as const },
    split: { kind: 'data' as const },
    subn: { kind: 'data' as const },
    sub: { kind: 'text' as const },
  },
  'sequence-matcher': {
    get_opcodes: { kind: 'data' as const },
    get_matching_blocks: { kind: 'data' as const },
    ratio: { kind: 'data' as const },
    quick_ratio: { kind: 'data' as const },
  },
  'json-decoder': { raw_decode: { kind: 'data' as const }, decode: { kind: 'data' as const } },
  Date: {
    toISOString: { kind: 'text' as const },
    toJSON: { kind: 'data' as const },
    toString: { kind: 'text' as const },
    getTime: { kind: 'data' as const },
    getFullYear: { kind: 'data' as const },
    getMonth: { kind: 'data' as const },
    getDate: { kind: 'data' as const },
    getUTCFullYear: { kind: 'data' as const },
  },
  Set: {
    has: { kind: 'data' as const },
    values: { kind: 'data' as const },
    keys: { kind: 'data' as const },
    entries: { kind: 'data' as const },
    delete: { kind: 'data' as const },
    clear: { kind: 'data' as const },
    add: { kind: 'builtin', name: 'Set' },
  },
  Map: {
    get: { kind: 'data' as const },
    has: { kind: 'data' as const },
    values: { kind: 'data' as const },
    keys: { kind: 'data' as const },
    entries: { kind: 'data' as const },
    delete: { kind: 'data' as const },
    clear: { kind: 'data' as const },
    set: { kind: 'builtin', name: 'Map' },
  },
  RegExp: { test: { kind: 'data' as const }, exec: { kind: 'data' as const } },
  URL: { toString: { kind: 'text' as const }, toJSON: { kind: 'text' as const } },
  URLSearchParams: {
    toString: { kind: 'text' as const },
    get: { kind: 'data' as const },
    getAll: { kind: 'data' as const },
    has: { kind: 'data' as const },
    entries: { kind: 'data' as const },
    keys: { kind: 'data' as const },
    values: { kind: 'data' as const },
  },
  datetime: {
    isoformat: { kind: 'text' as const },
    strftime: { kind: 'text' as const },
    timestamp: { kind: 'data' as const },
    date: { kind: 'data' as const },
    time: { kind: 'data' as const },
    total_seconds: { kind: 'data' as const },
  },
};
const builtinMethod = (receiver: string, name: string, args: readonly Value[]): Value | null => {
  if (receiver === 'transpiler') {
    return transpile(name, args);
  }
  const result =
    Object.hasOwn(builtinMethods, receiver) && Object.hasOwn(builtinMethods[receiver] ?? {}, name)
      ? builtinMethods[receiver]?.[name]
      : undefined;
  if (result !== undefined) {
    requireData(args);
    return result;
  }
  return null;
};

const builtinProperties: Readonly<Record<string, Readonly<Record<string, Value>>>> = {
  'process-result': {
    stdout: { kind: 'text' as const },
    stderr: { kind: 'text' as const },
    returncode: { kind: 'data' as const },
  },
  Map: { size: { kind: 'data' as const } },
  Set: { size: { kind: 'data' as const } },
  URL: {
    searchParams: { kind: 'builtin', name: 'URLSearchParams' },
    href: { kind: 'text' as const },
    origin: { kind: 'text' as const },
    protocol: { kind: 'text' as const },
    host: { kind: 'text' as const },
    hostname: { kind: 'text' as const },
    port: { kind: 'text' as const },
    pathname: { kind: 'text' as const },
    search: { kind: 'text' as const },
    hash: { kind: 'text' as const },
    username: { kind: 'text' as const },
    password: { kind: 'text' as const },
  },
  RegExp: {
    source: { kind: 'text' as const },
    flags: { kind: 'text' as const },
    global: { kind: 'data' as const },
    ignoreCase: { kind: 'data' as const },
    multiline: { kind: 'data' as const },
    unicode: { kind: 'data' as const },
    sticky: { kind: 'data' as const },
    dotAll: { kind: 'data' as const },
    lastIndex: { kind: 'data' as const },
  },
  datetime: {
    year: { kind: 'data' as const },
    month: { kind: 'data' as const },
    day: { kind: 'data' as const },
    hour: { kind: 'data' as const },
    minute: { kind: 'data' as const },
    second: { kind: 'data' as const },
    microsecond: { kind: 'data' as const },
    days: { kind: 'data' as const },
    seconds: { kind: 'data' as const },
    microseconds: { kind: 'data' as const },
  },
};
const builtinProperty = (receiver: string, member: string): Value | null =>
  Object.hasOwn(builtinProperties, receiver) &&
  Object.hasOwn(builtinProperties[receiver] ?? {}, member)
    ? (builtinProperties[receiver]?.[member] ?? null)
    : null;

const dataProperties = new Set([
  'process.argv',
  'process.platform',
  'process.version',
  'Bun.version',
  'datetime.timezone.utc',
  'sys.version',
  'sys.version_info',
  'sys.platform',
  'sys.argv',
  'Math.PI',
  'Math.E',
  'Math.LN2',
  'Math.LN10',
  'Number.MAX_SAFE_INTEGER',
  'Number.MIN_SAFE_INTEGER',
  'Number.NaN',
  'Number.POSITIVE_INFINITY',
  'Number.NEGATIVE_INFINITY',
  'math.pi',
  'math.e',
  'math.inf',
  'math.nan',
  're.S',
  're.I',
  're.M',
  're.X',
  're.A',
  're.DOTALL',
  're.IGNORECASE',
  're.MULTILINE',
  'string.ascii_letters',
  'string.ascii_lowercase',
  'string.ascii_uppercase',
  'string.digits',
  'string.hexdigits',
  'string.punctuation',
  'string.whitespace',
]);

export {
  builtinCall,
  builtinMethod,
  builtinProperty,
  dataProperties,
  builtinExceptions,
  isBuiltinException,
};
