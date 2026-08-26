from typing import Optional

import torch

from src.preprocessing.parser import ParsedRequest
from src.utils.config import get_settings

SPECIAL_TOKENS = {
    "<PAD>": 0,
    "<UNK>": 1,
    "<CLS>": 2,
    "<SEP>": 3,
    "<METHOD>": 4,
    "<PATH>": 5,
    "<PARAM>": 6,
    "<HEADER>": 7,
    "<BODY>": 8,
    "<IP>": 9,
    "<TS>": 10,
    "<UUID>": 11,
    "<TOKEN>": 12,
    "<NUM>": 13,
    "<EMAIL>": 14,
    "<EQ>": 15,
    "<AMP>": 16,
    "<SLASH>": 17,
    "<QMARK>": 18,
    "<DOT>": 19,
    "<COLON>": 20,
}


class Tokenizer:
    def __init__(self, vocab_size: Optional[int] = None):
        settings = get_settings()
        self.vocab_size = vocab_size or settings.model.vocab_size
        self.max_seq_len = settings.model.max_seq_len
        self.special_tokens = dict(SPECIAL_TOKENS)
        self._next_id = len(SPECIAL_TOKENS)

    def _tokenize_text(self, text: str) -> list[str]:
        tokens = []
        buf = ""
        for ch in text:
            if ch == "/":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<SLASH>")
            elif ch == "?":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<QMARK>")
            elif ch == "=":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<EQ>")
            elif ch == "&":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<AMP>")
            elif ch == ".":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<DOT>")
            elif ch == ":":
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
                tokens.append("<COLON>")
            elif ch.isspace():
                if buf:
                    tokens.extend(buf.split())
                    buf = ""
            else:
                buf += ch
        if buf:
            tokens.extend(buf.split())
        return tokens

    def _text_to_ids(self, text: str) -> list[int]:
        tokens = self._tokenize_text(text)
        ids = []
        for t in tokens:
            if t in self.special_tokens:
                ids.append(self.special_tokens[t])
            else:
                t_lower = t.lower()
                token_id = hash(t_lower) % (self.vocab_size - len(self.special_tokens)) + len(self.special_tokens)
                ids.append(token_id)
        return ids

    def encode_request(self, req: ParsedRequest) -> list[int]:
        ids: list[int] = [self.special_tokens["<CLS>"]]

        ids.append(self.special_tokens["<METHOD>"])
        ids.extend(self._text_to_ids(req.method))

        ids.append(self.special_tokens["<PATH>"])
        ids.extend(self._text_to_ids(req.path))

        for key, values in req.query_params.items():
            ids.append(self.special_tokens["<PARAM>"])
            ids.extend(self._text_to_ids(key))
            ids.append(self.special_tokens["<EQ>"])
            for v in values:
                ids.extend(self._text_to_ids(v))
                ids.append(self.special_tokens["<AMP>"])

        for key, value in req.headers.items():
            ids.append(self.special_tokens["<HEADER>"])
            ids.extend(self._text_to_ids(key))
            ids.append(self.special_tokens["<EQ>"])
            ids.extend(self._text_to_ids(value))

        if req.body:
            ids.append(self.special_tokens["<BODY>"])
            ids.extend(self._text_to_ids(req.body[:512]))

        ids.append(self.special_tokens["<SEP>"])

        if len(ids) > self.max_seq_len:
            ids = ids[: self.max_seq_len - 1] + [self.special_tokens["<SEP>"]]

        return ids

    def encode_batch(self, requests: list[ParsedRequest]) -> torch.Tensor:
        settings = get_settings()
        pad_id = self.special_tokens["<PAD>"]
        batch = []
        for req in requests:
            ids = self.encode_request(req)
            if len(ids) < self.max_seq_len:
                ids += [pad_id] * (self.max_seq_len - len(ids))
            batch.append(ids)
        return torch.tensor(batch, dtype=torch.long)

    def decode_ids(self, ids: list[int]) -> list[str]:
        reverse = {v: k for k, v in self.special_tokens.items()}
        return [reverse.get(i, f"<TOKEN_{i}>") for i in ids if i != self.special_tokens["<PAD>"]]
