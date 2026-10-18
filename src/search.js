export function buildFtsQuery(rawQuery) {
  const terms = String(rawQuery).toLocaleLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
  const tokens = terms.map(token => token.slice(0, 40)).slice(0, 10);
  return {
    tokens,
    match: tokens.map(token => `"${token.replaceAll('"', '""')}"*`).join(' AND '),
  };
}
