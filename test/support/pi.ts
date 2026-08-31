import type {
  PiExtensionContext,
  PiToolCallEvent,
  PiToolResultEvent,
  TripwirePiExtensionApi,
} from '../../src/pi-extension';

type ToolCallHandler = (
  event: PiToolCallEvent,
  context: PiExtensionContext,
) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>;

type ToolResultHandler = (event: PiToolResultEvent, context: PiExtensionContext) => Promise<void>;

type PiExtension = (api: TripwirePiExtensionApi) => void;

const isToolCallHandler = (value: unknown): value is ToolCallHandler => typeof value === 'function';

const isToolResultHandler = (value: unknown): value is ToolResultHandler =>
  typeof value === 'function';

const isPiExtension = (value: unknown): value is PiExtension => typeof value === 'function';

class PiHandlerCollector implements TripwirePiExtensionApi {
  toolCall: ToolCallHandler | undefined;

  toolResult: ToolResultHandler | undefined;

  on(event: 'tool_call', handler: ToolCallHandler): void;

  on(event: 'tool_result', handler: ToolResultHandler): void;

  on(event: 'tool_call' | 'tool_result', handler: unknown): void {
    if (event === 'tool_call' && isToolCallHandler(handler)) {
      this.toolCall = handler;
    } else if (event === 'tool_result' && isToolResultHandler(handler)) {
      this.toolResult = handler;
    }
  }

  requireToolCall(): ToolCallHandler {
    if (this.toolCall === undefined) {
      throw new Error('Pi extension did not register a tool_call handler');
    }
    return this.toolCall;
  }

  requireToolResult(): ToolResultHandler {
    if (this.toolResult === undefined) {
      throw new Error('Pi extension did not register a tool_result handler');
    }
    return this.toolResult;
  }
}

export { isPiExtension, PiHandlerCollector };
export type { PiExtension, ToolCallHandler, ToolResultHandler };
