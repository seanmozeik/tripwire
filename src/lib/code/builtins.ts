import { data, requireData, text } from './data';
import type { Value } from './types';

// Each entry is a callable contract. Import permission never authorizes a module's members.
const pureMembers = {
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
  re: ['search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'escape', 'compile'],
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
  process: ['cwd'],
  os: ['getcwd'],
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
  'type',
  'SystemExit',
]);

const builtinCall = (name: string, args: readonly Value[]): Value | null => {
  if (constructors.has(name) || (name.startsWith('datetime.') && pureCalls.has(name))) {
    requireData(args);
    return name === 'Array' ? data : { kind: 'builtin', name: name.split('.')[0] ?? name };
  }
  if (pureCalls.has(name) || conversions.has(name)) {
    requireData(args);
    return data;
  }
  if (name === 'crypto.createHash') {
    requireData(args);
    return { kind: 'hash' };
  }
  return null;
};

const builtinMethods: Readonly<Record<string, ReadonlySet<string>>> = {
  Date: new Set([
    'toISOString',
    'toJSON',
    'toString',
    'getTime',
    'getFullYear',
    'getMonth',
    'getDate',
    'getUTCFullYear',
  ]),
  Set: new Set(['has', 'values', 'keys', 'entries']),
  Map: new Set(['get', 'has', 'values', 'keys', 'entries']),
  RegExp: new Set(['test', 'exec']),
  URL: new Set(['toString', 'toJSON']),
  URLSearchParams: new Set(['get', 'getAll', 'has', 'entries', 'keys', 'values', 'toString']),
  datetime: new Set(['isoformat', 'strftime', 'timestamp', 'date', 'time', 'total_seconds']),
};
const builtinMethod = (receiver: string, name: string, args: readonly Value[]): Value | null => {
  if (['Map', 'Set'].includes(receiver) && ['set', 'add', 'delete', 'clear'].includes(name)) {
    requireData(args);
    return { kind: 'builtin', name: receiver };
  }
  if (Object.hasOwn(builtinMethods, receiver) && builtinMethods[receiver]?.has(name) === true) {
    requireData(args);
    return text;
  }
  return null;
};

const builtinProperty = (receiver: string, member: string): Value | null => {
  if (['Map', 'Set'].includes(receiver) && member === 'size') {
    return data;
  }
  if (receiver === 'URL' && member === 'searchParams') {
    return { kind: 'builtin', name: 'URLSearchParams' };
  }
  if (
    receiver === 'URL' &&
    [
      'href',
      'origin',
      'protocol',
      'host',
      'hostname',
      'port',
      'pathname',
      'search',
      'hash',
      'username',
      'password',
    ].includes(member)
  ) {
    return text;
  }
  if (
    receiver === 'RegExp' &&
    [
      'source',
      'flags',
      'global',
      'ignoreCase',
      'multiline',
      'unicode',
      'sticky',
      'dotAll',
      'lastIndex',
    ].includes(member)
  ) {
    return data;
  }
  if (
    receiver === 'datetime' &&
    [
      'year',
      'month',
      'day',
      'hour',
      'minute',
      'second',
      'microsecond',
      'days',
      'seconds',
      'microseconds',
    ].includes(member)
  ) {
    return data;
  }
  return null;
};

const dataProperties = new Set([
  'process.env',
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

export { builtinCall, builtinMethod, builtinProperty, dataProperties };
