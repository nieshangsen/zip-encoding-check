const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const UTF8_FLAG = 0x0800;
const EOCD_SCAN_BYTES = 65557;
const INITIAL_CENTRAL_DIRECTORY_READ = 1024 * 1024;
const SOFT_CENTRAL_DIRECTORY_READ_LIMIT = 16 * 1024 * 1024;
const HARD_CENTRAL_DIRECTORY_READ_LIMIT = 64 * 1024 * 1024;

const DECODERS = [
  { label: 'utf-8', decode: (bytes) => decodeText(bytes, 'utf-8') },
  { label: 'gbk', decode: (bytes) => decodeText(bytes, 'gbk') },
  { label: 'gb18030', decode: (bytes) => decodeText(bytes, 'gb18030') },
  { label: 'big5', decode: (bytes) => decodeText(bytes, 'big5') },
  { label: 'shift_jis', decode: (bytes) => decodeText(bytes, 'shift_jis') },
  { label: 'cp437', decode: (bytes) => decodeCp437(bytes) },
  { label: 'iso-8859-1', decode: (bytes) => decodeLatin1(bytes) },
];

const fileInput = document.querySelector('#zip-file');
const sampleInput = document.querySelector('#sample-size');
const allowLargeDirectoryInput = document.querySelector('#allow-large-directory');
const resultsElement = document.querySelector('#results');
const resultsHint = document.querySelector('#results-hint');
const entryTemplate = document.querySelector('#entry-template');
const decodeTemplate = document.querySelector('#decode-template');
const summaryStatus = document.querySelector('#summary-status');
const summaryTotal = document.querySelector('#summary-total');
const summarySampled = document.querySelector('#summary-sampled');
const summaryBytes = document.querySelector('#summary-bytes');

fileInput.addEventListener('change', () => analyzeSelectedFile().catch(renderFatalError));
sampleInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) {
    analyzeSelectedFile().catch(renderFatalError);
  }
});
allowLargeDirectoryInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) {
    analyzeSelectedFile().catch(renderFatalError);
  }
});

renderEmptyState('Choose a ZIP file to start.');

async function analyzeSelectedFile() {
  const file = fileInput.files?.[0];
  if (!file) {
    resetSummary();
    renderEmptyState('Choose a ZIP file to start.');
    return;
  }

  updateSummary('Reading ZIP metadata', '-', '-', '-');
  resultsHint.textContent = `Inspecting ${file.name} locally.`;

  const eocdInfo = await locateCentralDirectory(file);
  const { totalEntries, centralDirectoryOffset, centralDirectorySize } = eocdInfo;
  const requestedSample = clampSampleSize(Number(sampleInput.value) || 10);
  const metadataScan = await readCentralDirectorySample({
    file,
    centralDirectoryOffset,
    centralDirectorySize,
    totalEntries,
    requestedSample,
    allowLargeScan: allowLargeDirectoryInput.checked,
  });

  if (metadataScan.blocked) {
    updateSummary('Blocked by soft limit', String(totalEntries), '-', formatBytes(tailBuffer.byteLength));
    resultsHint.textContent = 'More central-directory metadata must be scanned to reach your sample.';
    renderEmptyState(
      `This ZIP needs more than ${formatBytes(SOFT_CENTRAL_DIRECTORY_READ_LIMIT)} of filename metadata scan. Enable “Allow analysis above soft limit” to continue.`
    );
    return;
  }

  const entries = metadataScan.entries;
  const bytesRead = eocdInfo.bytesRead + metadataScan.bytesRead;

  renderEntries(entries);
  updateSummary('Analysis complete', String(totalEntries), `${entries.length} of ${totalEntries}`, formatBytes(bytesRead));
  resultsHint.textContent = totalEntries > entries.length
    ? `Only the first ${entries.length} entries were sampled. File contents were not decompressed.`
    : 'All entries were inspected from metadata only.';
}

async function locateCentralDirectory(file) {
  const tailStart = Math.max(0, file.size - EOCD_SCAN_BYTES);
  const tailBuffer = await file.slice(tailStart, file.size).arrayBuffer();
  const tailView = new DataView(tailBuffer);
  const eocdOffset = findEndOfCentralDirectoryOffset(tailView);

  if (eocdOffset < 0) {
    throw new Error('Could not find ZIP end-of-central-directory record.');
  }

  const eocdInfo = {
    totalEntries: tailView.getUint16(eocdOffset + 10, true),
    centralDirectorySize: tailView.getUint32(eocdOffset + 12, true),
    centralDirectoryOffset: tailView.getUint32(eocdOffset + 16, true),
    bytesRead: tailBuffer.byteLength,
  };

  const needsZip64 =
    eocdInfo.totalEntries === 0xffff ||
    eocdInfo.centralDirectorySize === 0xffffffff ||
    eocdInfo.centralDirectoryOffset === 0xffffffff;

  if (!needsZip64) {
    return eocdInfo;
  }

  const locatorOffset = eocdOffset - 20;
  if (locatorOffset < 0 || tailView.getUint32(locatorOffset, true) !== ZIP64_EOCD_LOCATOR_SIGNATURE) {
    throw new Error('ZIP64 locator not found for large ZIP file.');
  }

  const zip64RecordOffset = toSafeNumber(readUint64LE(tailView, locatorOffset + 8), 'ZIP64 EOCD offset');
  const zip64HeaderBuffer = await file.slice(zip64RecordOffset, zip64RecordOffset + 56).arrayBuffer();
  const zip64View = new DataView(zip64HeaderBuffer);

  if (zip64View.byteLength < 56 || zip64View.getUint32(0, true) !== ZIP64_EOCD_SIGNATURE) {
    throw new Error('ZIP64 end-of-central-directory record not found.');
  }

  return {
    totalEntries: toSafeNumber(readUint64LE(zip64View, 32), 'ZIP64 total entries'),
    centralDirectorySize: toSafeNumber(readUint64LE(zip64View, 40), 'ZIP64 central directory size'),
    centralDirectoryOffset: toSafeNumber(readUint64LE(zip64View, 48), 'ZIP64 central directory offset'),
    bytesRead: tailBuffer.byteLength + zip64HeaderBuffer.byteLength,
  };
}

async function readCentralDirectorySample({
  file,
  centralDirectoryOffset,
  centralDirectorySize,
  totalEntries,
  requestedSample,
  allowLargeScan,
}) {
  const targetEntries = Math.min(requestedSample, totalEntries);

  if (centralDirectorySize > HARD_CENTRAL_DIRECTORY_READ_LIMIT && !allowLargeScan) {
    throw new Error(
      `This ZIP needs more than ${formatBytes(HARD_CENTRAL_DIRECTORY_READ_LIMIT)} of central-directory scan for browser analysis.`
    );
  }

  let bytesToRead = Math.min(centralDirectorySize, INITIAL_CENTRAL_DIRECTORY_READ);

  while (bytesToRead <= centralDirectorySize) {
    if (bytesToRead > SOFT_CENTRAL_DIRECTORY_READ_LIMIT && !allowLargeScan) {
      return { blocked: true, entries: [], bytesRead: 0 };
    }

    if (bytesToRead > HARD_CENTRAL_DIRECTORY_READ_LIMIT) {
      throw new Error(
        `This ZIP needs more than ${formatBytes(HARD_CENTRAL_DIRECTORY_READ_LIMIT)} of central-directory scan for browser analysis.`
      );
    }

    const directoryBuffer = await file
      .slice(centralDirectoryOffset, centralDirectoryOffset + bytesToRead)
      .arrayBuffer();

    const parseResult = parseCentralDirectory(directoryBuffer, targetEntries, totalEntries, bytesToRead >= centralDirectorySize);
    if (!parseResult.needsMoreData || parseResult.entries.length >= targetEntries || bytesToRead >= centralDirectorySize) {
      return {
        blocked: false,
        entries: parseResult.entries,
        bytesRead: directoryBuffer.byteLength,
      };
    }

    bytesToRead = Math.min(centralDirectorySize, bytesToRead * 2);
  }

  return { blocked: false, entries: [], bytesRead: 0 };
}

function parseCentralDirectory(arrayBuffer, sampleSize, totalEntries, reachedDirectoryEnd = false) {
  const dataView = new DataView(arrayBuffer);
  const entries = [];
  let cursor = 0;
  let seenEntries = 0;

  while (cursor + 46 <= dataView.byteLength && seenEntries < totalEntries && entries.length < sampleSize) {
    const signature = dataView.getUint32(cursor, true);
    if (signature !== CENTRAL_DIRECTORY_SIGNATURE) {
      return {
        entries,
        needsMoreData: false,
      };
    }

    const flagBits = dataView.getUint16(cursor + 8, true);
    const compressedSize = dataView.getUint32(cursor + 20, true);
    const uncompressedSize = dataView.getUint32(cursor + 24, true);
    const fileNameLength = dataView.getUint16(cursor + 28, true);
    const extraFieldLength = dataView.getUint16(cursor + 30, true);
    const fileCommentLength = dataView.getUint16(cursor + 32, true);
    const externalAttributes = dataView.getUint32(cursor + 38, true);
    const recordLength = 46 + fileNameLength + extraFieldLength + fileCommentLength;

    if (cursor + recordLength > dataView.byteLength) {
      return {
        entries,
        needsMoreData: !reachedDirectoryEnd,
      };
    }

    const nameStart = cursor + 46;
    const nameEnd = nameStart + fileNameLength;
    const rawName = new Uint8Array(arrayBuffer.slice(nameStart, nameEnd));
    const isDirectory = rawName.at(-1) === 0x2f || (externalAttributes & 0x10) === 0x10;

    entries.push({
      index: seenEntries + 1,
      kind: isDirectory ? 'Directory' : 'File',
      flagBits,
      compressedSize,
      uncompressedSize,
      rawName,
      decodings: DECODERS.map((decoder) => ({
        label: decoder.label,
        value: decoder.decode(rawName),
      })),
    });

    seenEntries += 1;
    cursor += recordLength;
  }

  return {
    entries,
    needsMoreData: seenEntries < totalEntries && entries.length < sampleSize && !reachedDirectoryEnd,
  };
}

function findEndOfCentralDirectoryOffset(dataView) {
  for (let offset = dataView.byteLength - 22; offset >= 0; offset -= 1) {
    if (dataView.getUint32(offset, true) !== EOCD_SIGNATURE) {
      continue;
    }

    return offset;
  }

  return -1;
}

function readUint64LE(dataView, offset) {
  const low = BigInt(dataView.getUint32(offset, true));
  const high = BigInt(dataView.getUint32(offset + 4, true));
  return (high << 32n) | low;
}

function toSafeNumber(value, label) {
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  if (value > maxSafe) {
    throw new Error(`${label} exceeds browser safe integer range.`);
  }

  return Number(value);
}

function decodeText(bytes, encoding) {
  try {
    return new TextDecoder(encoding, { fatal: false }).decode(bytes);
  } catch {
    return '[unsupported by this browser]';
  }
}

function decodeLatin1(bytes) {
  let output = '';
  for (const byte of bytes) {
    output += String.fromCharCode(byte);
  }
  return output;
}

function decodeCp437(bytes) {
  let output = '';
  for (const byte of bytes) {
    output += String.fromCodePoint(CP437_TABLE[byte] ?? 0xfffd);
  }
  return output;
}

function renderEntries(entries) {
  resultsElement.innerHTML = '';
  if (entries.length === 0) {
    renderEmptyState('No entries were found in the central directory sample.');
    return;
  }

  for (const entry of entries) {
    const node = entryTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector('.entry-index').textContent = `Entry ${entry.index}`;
    node.querySelector('.entry-title').textContent = `${entry.kind} • ${formatBytes(entry.uncompressedSize)} uncompressed`;
    node.querySelector('.flag-badge').textContent = (entry.flagBits & UTF8_FLAG) === UTF8_FLAG
      ? 'UTF-8 flag set'
      : 'UTF-8 flag not set';
    node.querySelector('.hex-value').textContent = bytesToHex(entry.rawName);
    node.querySelector('.byte-length').textContent = String(entry.rawName.length);
    node.querySelector('.flag-value').textContent = `0x${entry.flagBits.toString(16).padStart(4, '0')}`;

    const decodeList = node.querySelector('.decode-list');
    for (const decoding of entry.decodings) {
      const row = decodeTemplate.content.firstElementChild.cloneNode(true);
      row.querySelector('.decode-name').textContent = decoding.label;
      row.querySelector('.decode-value').textContent = decoding.value;
      decodeList.appendChild(row);
    }

    resultsElement.appendChild(node);
  }
}

function renderEmptyState(message) {
  resultsElement.innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function renderFatalError(error) {
  renderEmptyState(error.message);
  resultsHint.textContent = 'Analysis failed.';
  updateSummary('Error', '-', '-', '-');
}

function updateSummary(status, total, sampled, bytesRead) {
  summaryStatus.textContent = status;
  summaryStatus.classList.toggle('status-error', status === 'Error' || status === 'Blocked by soft limit');
  summaryTotal.textContent = total;
  summarySampled.textContent = sampled;
  summaryBytes.textContent = bytesRead;
}

function resetSummary() {
  updateSummary('Waiting for file', '-', '-', '-');
  resultsHint.textContent = 'Choose a ZIP file to start.';
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function clampSampleSize(value) {
  return Math.min(100, Math.max(1, value));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join(' ');
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

const CP437_TABLE = [
  0x0000, 0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022,
  0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a, 0x266b, 0x263c,
  0x25ba, 0x25c4, 0x2195, 0x203c, 0x00b6, 0x00a7, 0x25ac, 0x21a8,
  0x2191, 0x2193, 0x2192, 0x2190, 0x221f, 0x2194, 0x25b2, 0x25bc,
  0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
  0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
  0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
  0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
  0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
  0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
  0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
  0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
  0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
  0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
  0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
  0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x2302,
  0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,
  0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
  0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
  0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,
  0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
  0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
  0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
  0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
  0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
  0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
  0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4,
  0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
  0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
  0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,
];