export type Message<Label extends Exclude<string, Label>, T> = Record<Label, T>

export interface Channel {
  send<Label extends Exclude<string, Label>, T>(
    message: Message<Label, T>
  ): Promise<void>
  receive<Label extends Exclude<string, Label>, T>(): Promise<Message<Label, T>>
}
