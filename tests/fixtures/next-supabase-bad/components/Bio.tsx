export function Bio({ bio }: { bio: string }) {
  return <section dangerouslySetInnerHTML={{ __html: bio }} />
}
