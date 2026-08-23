const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const root = __dirname;
const metadata = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const files = [
  ["package.json", path.join(root, "package.json")],
  ["extension.js", path.join(root, "extension.js")],
  ["README.md", path.join(root, "README.md")],
  ["LICENSE", path.resolve(root, "../../LICENSE")],
  ["NOTICE", path.resolve(root, "../../NOTICE")],
  ["SECURITY.md", path.resolve(root, "../../SECURITY.md")],
  ["THIRD_PARTY_NOTICES.md", path.resolve(root, "../../THIRD_PARTY_NOTICES.md")],
];
const manifest = `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Id="${metadata.publisher}.${metadata.name}" Version="${metadata.version}" Language="en-US" Publisher="${metadata.publisher}" />
    <DisplayName>${metadata.displayName}</DisplayName>
    <Description xml:space="preserve">${metadata.description}</Description>
    <Tags>binary,analysis,decompiler</Tags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${metadata.engines.vscode}" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" Version="[1.0,]" />
  </Installation>
  <Dependencies />
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" />
  </Assets>
</PackageManifest>
`;

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value, 0);
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value >>> 0, 0);
  return out;
}

function zipEntry(name, content, offset) {
  const nameBytes = Buffer.from(name, "utf8");
  const source = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  const compressed = zlib.deflateRawSync(source, { level: 9 });
  const crc = crc32(source);
  const local = Buffer.concat([
    u32(0x04034b50), u16(20), u16(0), u16(8), u16(0), u16(0), u32(crc),
    u32(compressed.length), u32(source.length), u16(nameBytes.length), u16(0), nameBytes, compressed,
  ]);
  const central = Buffer.concat([
    u32(0x02014b50), u16(20), u16(20), u16(0), u16(8), u16(0), u16(0), u32(crc),
    u32(compressed.length), u32(source.length), u16(nameBytes.length), u16(0), u16(0), u16(0), u16(0),
    u32(0), u32(offset), nameBytes,
  ]);
  return { local, central };
}

const entries = [
  ["extension.vsixmanifest", manifest],
  ...files.map(([name, source]) => [
    `extension/${name}`,
    fs.readFileSync(source),
  ]),
];
const locals = [];
const centrals = [];
let offset = 0;
for (const [name, content] of entries) {
  const entry = zipEntry(name, content, offset);
  locals.push(entry.local);
  centrals.push(entry.central);
  offset += entry.local.length;
}
const centralDirectory = Buffer.concat(centrals);
const end = Buffer.concat([
  u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length),
  u32(centralDirectory.length), u32(offset), u16(0),
]);
const outputDir = path.join(root, "dist");
fs.mkdirSync(outputDir, { recursive: true });
const output = path.join(outputDir, `${metadata.name}-${metadata.version}.vsix`);
fs.writeFileSync(output, Buffer.concat([...locals, centralDirectory, end]));
console.log(output);
