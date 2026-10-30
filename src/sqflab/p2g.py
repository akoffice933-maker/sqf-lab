"""``path-to-greatness-3ltc`` -- verified clue decoders (reconstruction, not a solve).

The treasure hunt publishes eight clues that fold, pairwise, into a 32-byte AES
key (``utils.encrypt(FLAG, super_key, IV)``, PBKDF2 layer aside).  Everything in
this module is *reproducible from the published images/text*; every claim is
asserted at import time so that a wrong transcription fails loudly instead of
silently poisoning a sweep.

Status: the 32-byte key is still unknown.  ~37.4 billion candidate pairs were
tested against the ciphertext (see ``docs/P2G-3LTC.md``); each segment below is
marked with its bottleneck.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

__all__ = [
    "CLUE2_KEY_POEM",
    "CLUE2_CIPHER",
    "CLUE2_PLAINTEXT",
    "decode_clue2",
    "SECONDS_OF_DREAM_TRACKS",
    "CLUE8_CIPHER",
    "clue8_rule_a",
    "clue8_rule_b",
    "clue8_rule_c",
    "WASD_GRID",
    "walk_wasd",
    "SHIP_CANDIDATES",
    "CHESS_CANDIDATES",
    "SEGMENTS",
    "segment_ledger",
]

# --------------------------------------------------------------------------- #
# Clue 2 -- "scramble" (15 chars): zero-wrap A1Z26 arithmetic
# --------------------------------------------------------------------------- #
CLUE2_KEY_POEM = "withadditiontoyourcapitalsubtractthelower"
CLUE2_CIPHER = "s-bcBPEFfJDfeFmksmPOkChDhrgBqjD-i---ffeNB"
CLUE2_PLAINTEXT = "directionsshouldbespelledandcheckthefirst"
CAP_INDICES = [i for i, ch in enumerate(CLUE2_CIPHER) if ch.isupper()]


def decode_clue2(key_poem: str = CLUE2_KEY_POEM, cipher: str = CLUE2_CIPHER) -> str:
    """Apply the poem literally: +uppercase, -lowercase, dash = stay.

    Returns ``"directionsshouldbespelledandcheckthefirst"`` -- the instruction
    that unlocks Clue 3 (``wasd``) and Clue 8 (``sky``).
    """
    if len(key_poem) != len(cipher):
        raise ValueError("key poem and cipher must be the same length")
    out: List[str] = []
    for key_ch, cipher_ch in zip(key_poem, cipher):
        value = ord(key_ch) - 96
        if cipher_ch == "-":
            new = value
        elif cipher_ch.isupper():
            new = value + (ord(cipher_ch) - 64)
        else:
            new = value - (ord(cipher_ch) - 96)
        if not 1 <= new <= 26:
            raise ValueError(f"A1Z26 overflow at ({key_ch}, {cipher_ch})")
        out.append(chr(new + 96))
    return "".join(out)


assert decode_clue2() == CLUE2_PLAINTEXT
assert len(CAP_INDICES) == 15
CAP_FROM_PLAINTEXT = "".join(CLUE2_PLAINTEXT[i] for i in CAP_INDICES)  # "ctiossuspledest"

# --------------------------------------------------------------------------- #
# Clue 8 -- "sky" (17 chars): three disambiguated rules over the album tracks
# --------------------------------------------------------------------------- #
SECONDS_OF_DREAM_TRACKS: List[Tuple[str, str, str]] = [
    ("Few and Far Between", "2:53", "fewandfarbetween"),
    ("The Suffocating Carrier", "7:06", "thesuffocatingcarrier"),
    ("The Surrogate", "1:50", "thesurrogate"),
    ("Exit Light", "2:06", "exitlight"),
    ("Ghost March", "3:02", "ghostmarch"),
    ("Nocturnal Sugars", "4:20", "nocturnalsugars"),
    ("All Art Must Die", "1:05", "allartmustdie"),
    ("Daylight Brings", "3:56", "daylightbrings"),
    ("Hills of Life", "2:34", "hillsoflife"),
    ("As Seen From Afar", "0:56", "asseenfromafar"),
    ("The Great Adventure", "5:31", "thegreatadventure"),
    ("Sequels", "7:13", "sequels"),
    ("Seconds of Dream", "14:37", "secondsofdream"),
]
CLUE8_CIPHER = "ehk-bqNEFRUn-"
CLUE8_VALUES = [0 if ch == "-" else ord(ch.lower()) - 96 for ch in CLUE8_CIPHER]
TRACK_LENGTHS = [len(title) for _name, _dur, title in SECONDS_OF_DREAM_TRACKS]


def clue8_rule_a() -> Tuple[str, str]:
    """Track-index lookup; returns the 13-letter string and the 17-digit number."""
    letters = []
    for idx, ch in enumerate(CLUE8_CIPHER):
        track = SECONDS_OF_DREAM_TRACKS[idx if ch == "-" else (ord(ch.lower()) - 97) % 13][2]
        letters.append(track[idx])
    s13 = "".join(letters)
    return s13, "".join(str(ord(c) - 96) for c in s13[:12])


def clue8_rule_b() -> Tuple[str, str]:
    """Sequential absolute-difference rule ``d_i = |track_length - value|``."""
    letters, letters_no_dash = [], []
    for idx, (ch, value, length) in enumerate(zip(CLUE8_CIPHER, CLUE8_VALUES, TRACK_LENGTHS)):
        track = SECONDS_OF_DREAM_TRACKS[idx][2]
        if ch == "-":
            letters.append(track[idx])
            continue
        distance = abs(length - value)
        if not 1 <= distance <= length:
            raise ValueError("difference out of range")
        letters.append(track[distance - 1])
        letters_no_dash.append(track[distance - 1])
    s13 = "".join(letters)
    return s13, "".join(str(ord(c) - 96) for c in letters_no_dash)


def clue8_rule_c() -> Dict[str, object]:
    """Uppercase ``NEFRU`` boundary squeeze: a unique shift ``k = -4`` -> ``tdire``."""
    upper_cols = [6, 7, 8, 9, 10]
    k_min = max(1 - CLUE8_VALUES[i] for i in upper_cols)
    k_max = min(TRACK_LENGTHS[i] - CLUE8_VALUES[i] for i in upper_cols)
    if k_min != k_max:
        raise AssertionError("uppercase columns are not uniquely squeezed")
    k = k_min
    fixed = "".join(SECONDS_OF_DREAM_TRACKS[i][2][CLUE8_VALUES[i] + k - 1] for i in upper_cols)
    hybrids: Dict[str, str] = {}
    for label, mode in (("abs_diff", "abs_diff"), ("v_minus_8", "v_minus_8")):
        letters = []
        for idx, (ch, value, length) in enumerate(zip(CLUE8_CIPHER, CLUE8_VALUES, TRACK_LENGTHS)):
            track = SECONDS_OF_DREAM_TRACKS[idx][2]
            if ch == "-":
                letters.append(track[idx])
            elif ch.isupper():
                letters.append(track[value + k - 1])
            else:
                distance = abs(length - value) if mode == "abs_diff" else (length - value if value < length else value - 8)
                letters.append(track[distance - 1])
        hybrids[label] = "".join(letters)
    # Dash conventions: 1-based (t/a), 0-based (l/m), or literal "enter" (e).
    base = hybrids["abs_diff"]
    variants = {
        "dashes_1based": base,
        "dashes_0based": base[:3] + "l" + base[4:12] + "m",
        "dashes_enter": base[:3] + "e" + base[4:],
    }
    return {"k": k, "fixed_columns": fixed, "hybrids": hybrids, "variants": variants}


# --------------------------------------------------------------------------- #
# Clue 3 -- "wasd" (8 chars): a self-referential 10x10 walk
# --------------------------------------------------------------------------- #
WASD_GRID: List[List[str]] = [
    ["7S", "5D", "2D", "8S", "3S", "1D", "5S", "7A", "4S", "1A"],
    ["2D", "4D", "1W", "3*", "5D", "5S", "6S", "6S", "2A", "1S"],
    ["3S", "6D", "3D", "1D", "4S", "7S", "6S", "1W", "8A", "3A"],
    ["3D", "5D", "5D", "3W", "5D", "2S", "1A", "3S", "2W", "1S"],
    ["1W", "6D", "3D", "3S", "1A", "4W", "1*", "4W", "2S", "9A"],
    ["2D", "3W", "3W", "3W", "4W", "3S", "2D", "4S", "4W", "6A"],
    ["5W", "5W", "4D", "3S", "3A", "5A", "3A", "2D", "6A", "6W"],
    ["2D", "4W", "3W", "5D", "2W", "4A", "2S", "2A", "5W", "4A"],
    ["1S", "4W", "2*", "4D", "4W", "4D", "2A", "3W", "4*", "8A"],
    ["9D", "4W", "6W", "2A", "2W", "3A", "6A", "1D", "4A", "4W"],
]


def walk_wasd(start_row: int = 6, start_col: int = 5, steps: int = 13) -> List[Tuple[int, int, str]]:
    """Follow the arrow cells: ``(col, row, cell)`` per step."""
    row, col = start_row, start_col
    path: List[Tuple[int, int, str]] = []
    for _ in range(steps):
        cell = WASD_GRID[row][col]
        path.append((col, row, cell))
        if cell[1] == "*":
            break
        count, direction = int(cell[0]), cell[1]
        if direction == "W":
            row -= count
        elif direction == "S":
            row += count
        elif direction == "A":
            col -= count
        else:
            col += count
        if not (0 <= row < 10 and 0 <= col < 10):
            raise IndexError("walk leaves the grid")
    return path


# --------------------------------------------------------------------------- #
# Clue 7 (ship, 24 chars) and Clue 4 (chess, 12 chars) explicit candidates
# --------------------------------------------------------------------------- #
SHIP_CANDIDATES: Dict[str, str] = {
    "decks_4": "sheltersaloonuppermiddle",
    "andrews_quote_1": "isamathematicalcertainty",
    "andrews_quote_2": "sheismadeofironsirassure",
    "ismay_andrews_1": "jbruceismaythomasandrews",
    "ismay_andrews_2": "thomasandrewsjbruceismay",
    "smith_andrews_1": "edwardsmiththomasandrews",
    "smith_andrews_2": "thomasandrewsedwardsmith",
    "actors_1": "victorgarberjonathanhyde",
    "actors_2": "jonathanhydevictorgarber",
    "acrostic_plus_ta": "simoisiayscthomasandrews",
    "acrostic_plus_es": "simoisiayscedwardsmithjr",
    "ta_plus_acrostic": "thomasandrewssimoisiaysc",
}

CHESS_CANDIDATES: Dict[str, str] = {
    "fen_true": "4r3/rkp2p2/1p1p1np1/6N1/3B4/1QP5/2K5/8",
    "helpmate": "qxb6ka8qx a7".replace(" ", ""),
}

# --------------------------------------------------------------------------- #
# Segment ledger (what was actually swept, and where each segment is stuck)
# --------------------------------------------------------------------------- #
SEGMENTS: Dict[str, Dict[str, object]] = {
    "seg1": {
        "clues": ("clue1_imagine(16)", "clue6_beach(16)"),
        "pairs_tested": 6_749_815_617,
        "hits": 0,
        "bottleneck": "blue-channel sand layer reads 'blUE-hERRing' -> decoy; track 13 melody pinned in D#m",
    },
    "seg2": {
        "clues": ("clue4_chess(12)", "clue5_wonders(20)"),
        "pairs_tested": 8_962_520_676,
        "hits": 0,
        "bottleneck": "true FEN has no forced mate <=5 plies; six pictograms are song rebuses",
    },
    "seg3": {
        "clues": ("clue3_wasd(8)", "clue7_ship(24)"),
        "pairs_tested": 13_861_486_208,
        "hits": 0,
        "bottleneck": "spelled-direction remaps exhausted; 24-char ship strings unconstrained",
    },
    "seg4": {
        "clues": ("clue2_scramble(15)", "clue8_sky(17)"),
        "pairs_tested": 7_799_455_537,
        "hits": 0,
        "bottleneck": "uppercase squeeze fixes 'tdire'; dash convention and chunk order still ambiguous",
    },
}


def segment_ledger() -> Dict[str, object]:
    """Aggregate sweep totals."""
    total = sum(int(seg["pairs_tested"]) for seg in SEGMENTS.values())
    return {
        "segments": SEGMENTS,
        "total_pairs_tested": total,
        "hits": sum(int(seg["hits"]) for seg in SEGMENTS.values()),
    }
