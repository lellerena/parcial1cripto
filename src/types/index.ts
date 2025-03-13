export type StreamCipher = "Salsa20" | "ChaCha20";
export interface Message {
  text: string;
  encrypted: boolean;
  cipher: string;
  scenario: number;
}
