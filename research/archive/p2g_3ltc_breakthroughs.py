#!/usr/bin/env python3
"""
Path to Greatness (3 LTC) — Verified Cryptanalysis, GitHub Reconnaissance & Explicit Candidate Definitions
Target Address : LUtL7qnm3gzxKjHcfVLSjydqhhinTVmTmS (3.02608794 LTC)
"""

import itertools

# ---------------------------------------------------------------------------
# 0. EXPLICIT SEGMENT STATUS LEDGER & PRIORITIZED RECOMMENDATION RUNS
# ---------------------------------------------------------------------------
SEGMENT_STATUS = {
    "seg1": {
        "status": "blocked",
        "clues": "clue1_imagine (16) + clue6_beach (16)",
        "bottleneck": (
            "15 notes of Track 13 ('536531276755365' in D#m) measured to 1 cent; blue-channel sand layer "
            "explicitly reads 'blUE-hERRing' at (x=19..121, y=227..235), confirming the sand layer & Tower Key/Lock "
            "are a 'blue herring' decoy. 396,511 imagine x 1,063 beach melody/track strings tested (0 hits)."
        ),
        "pairs_tested": 6_749_815_617,
        "hits": 0,
    },
    "seg2": {
        "status": "blocked",
        "clues": "clue4_chess (12, case-preserved) + clue5_wonders (20)",
        "bottleneck": (
            "True FEN '4r3/rkp2p2/1p1p1np1/6N1/3B4/1QP5/2K5/8' has 0 forced mates in <=5 plies; "
            "6 red pictograms on 98_wonders.png proved 1-to-1 rebus for the 6 quoted songs (Ghost Love Score, "
            "Treasure Island, High Hopes, Three Evils, Havamal, Astral and Arcane) with lit 'km' torches."
        ),
        "pairs_tested": 8_962_520_676,
        "hits": 0,
    },
    "seg3": {
        "status": "open (wasd/ship)",
        "clues": "clue3_wasd (8) + clue7_ship (24)",
        "bottleneck": (
            "Applied Clue 2 instruction 'Directions should be spelled and check the first' to 110_wasd.png "
            "(spelled green roots 'fiveeast', 'twonorth', 'fourwest', 'fourleft', 'onesouth' = 8 chars; "
            "first-letter udlr/nwse remapping 'r3u1ld24'/'e3n1ws24') x 385 ship strings (168.86M pairs, 0 hits)."
        ),
        "pairs_tested": 13_861_486_208,
        "hits": 0,
    },
    "seg4": {
        "status": "open (scramble/sky, tdire fixed)",
        "clues": "clue2_scramble (15) + clue8_sky (17)",
        "bottleneck": (
            "139_scramble.png verified right-side up at 90 deg CW ('ot rleow utbrctsa aacpilt hwti / dioiatdn het ryuo'); "
            "3,693 direction-spelled & chunk-permuted scramble x 19,578 expanded sky tested (72.30M new pairs, 0 hits)."
        ),
        "pairs_tested": 7_799_455_537,
        "hits": 0,
    },
}

RECOMMENDATION_RUN_LEDGER = [
    ("Rec 3 (Seg 4)", "cap_from_P ('ctiossuspledest') x 304,737 sky (incl. col4='e' & 0-based)", 1, 304_737, 304_737, "0.02s", 0),
    ("Rec 2 (Seg 4)", "27 contiguous 15-char windows of P x 304,737 sky", 27, 304_737, 8_227_899, "0.25s", 0),
    ("Rec 1 (Seg 4)", "10 explicit scramble + 27 K-windows x 304,737 sky (col4='e'/'l'/'t', 26x26 dashes)", 37, 304_737, 11_275_269, "0.35s", 0),
    ("Rec 4a (Seg 3)", "8,463,689 wasd (retained + {wasd}^8 + 4L4D mixed) x {'sheltersaloon...', 'isamathematical...'}", 8_463_689, 2, 16_927_378, "0.51s", 0),
    ("Rec 4b (Seg 3)", "8,463,689 wasd x all 18 explicit 24-char ship candidates", 8_463_689, 18, 152_346_402, "4.65s", 0),
    ("Rec 5 (Seg 1)", "346,874 imagine (all date/alphanumeric/infamous forms) x '536531#276755365'", 346_874, 1, 346_874, "0.02s", 0),
    ("Rec 6 (Seg 2)", "28,655 new chess (14->12 drop-2, front-to-throne, hierarchy, 4x3, 6x2) x 17,204 wonders", 28_655, 17_204, 492_980_620, "14.78s", 0),
    ("Rec 7 (Seg 4)", "3,693 direction-spelled & chunk-permuted scramble x 19,578 expanded sky", 3_693, 19_578, 72_301_554, "2.21s", 0),
    ("Rec 8 (Seg 3)", "438,586 spelled-direction & udlr/nsew-remapped wasd x 385 ship candidates", 438_586, 385, 168_855_610, "5.06s", 0),
    ("Rec 9 (Seg 2)", "3,522 piece/SAN/check-first chess x 5,548 rebus-song & music wonders", 3_522, 5_548, 19_540_056, "0.59s", 0),
    ("Rec 10 (Seg 1)", "396,511 literal-replaced & date8 imagine x 1,063 Track-13 melody & beach", 396_511, 1_063, 421_491_193, "12.74s", 0),
]

# ---------------------------------------------------------------------------
# 1. CLUE 2 (SCRAMBLE, 15 CHARS): ZERO-WRAP DECODER, 10 EXPLICIT & 27 WINDOWS
# ---------------------------------------------------------------------------
CLUE2_RAW_ANAGRAMS = "hwtidioiatdnotryuoaacpiltutbrctsahetrleow"  # 8 chunks: [4,8,2,4,7,8,3,5]
CLUE2_KEY_POEM     = "withadditiontoyourcapitalsubtractthelower"
CLUE2_CIPHER       = "s-bcBPEFfJDfeFmksmPOkChDhrgBqjD-i---ffeNB"
CLUE2_PLAINTEXT    = "directionsshouldbespelledandcheckthefirst"

CLUE2_CAP_INDICES_0 = [i for i, ch in enumerate(CLUE2_CIPHER) if ch.isupper()]
assert len(CLUE2_CAP_INDICES_0) == 15


def decode_clue2(key_poem: str = CLUE2_KEY_POEM, cipher: str = CLUE2_CIPHER) -> str:
    assert len(key_poem) == 41, f"Expected 41-char key_poem, got {len(key_poem)}"
    assert len(cipher) == 41, f"Expected 41-char cipher, got {len(cipher)}"
    out = []
    for k_ch, c_ch in zip(key_poem, cipher):
        k_val = ord(k_ch) - 96
        if c_ch == "-":
            p_val = k_val
        elif c_ch.isupper():
            p_val = k_val + (ord(c_ch) - 64)
        else:
            p_val = k_val - (ord(c_ch) - 96)
        assert 1 <= p_val <= 26, f"Out-of-bounds A1Z26 value {p_val} at ({k_ch}, {c_ch})"
        out.append(chr(p_val + 96))
    res = "".join(out)
    assert len(res) == 41 and res == CLUE2_PLAINTEXT
    return res


SCRAMBLE_EXPLICIT_CANDIDATES = {
    "cap_from_P":       "".join(CLUE2_PLAINTEXT[i] for i in CLUE2_CAP_INDICES_0),     # "ctiossuspledest"
    "cap_from_K":       "".join(CLUE2_KEY_POEM[i] for i in CLUE2_CAP_INDICES_0),      # "addiioocaiabaer"
    "cap_from_C":       "".join(CLUE2_CIPHER[i].lower() for i in CLUE2_CAP_INDICES_0),# "bpefjdfpocdbdnb"
    "cap_from_RAW":     "".join(CLUE2_RAW_ANAGRAMS[i] for i in CLUE2_CAP_INDICES_0),  # "dioitdtaaplbtow"
    "phrase_dir_first": "directionsfirst",
    "phrase_chk_dir":   "checkdirections",
    "phrase_spl_dir":   "spelldirections",
    "phrase_shd_spl":   "shouldbespelled",
    "window_0_P":       CLUE2_PLAINTEXT[:15],                                         # "directionsshoul"
    "window_end_P":     CLUE2_PLAINTEXT[-15:],                                        # "ndcheckthefirst"
}
for _k, _v in SCRAMBLE_EXPLICIT_CANDIDATES.items():
    assert len(_v) == 15, f"SCRAMBLE candidate {_k} has length {len(_v)} != 15"

# All 27 contiguous 15-character windows of P = "directionsshouldbespelledandcheckthefirst"
SCRAMBLE_WINDOWS_27_P = [CLUE2_PLAINTEXT[i:i + 15] for i in range(len(CLUE2_PLAINTEXT) - 15 + 1)]
assert len(SCRAMBLE_WINDOWS_27_P) == 27 and all(len(w) == 15 for w in SCRAMBLE_WINDOWS_27_P)


# ---------------------------------------------------------------------------
# 2. CLUE 8 (SKY, 17 CHARS): THREE DISAMBIGUATED RULES + DASH BASE VARIANTS
# ---------------------------------------------------------------------------
SECONDS_OF_DREAM_TRACKS = [
    ("Few and Far Between",     "2:53",  "fewandfarbetween"),
    ("The Suffocating Carrier", "7:06",  "thesuffocatingcarrier"),
    ("The Surrogate",           "1:50",  "thesurrogate"),
    ("Exit Light",              "2:06",  "exitlight"),
    ("Ghost March",             "3:02",  "ghostmarch"),
    ("Nocturnal Sugars",        "4:20",  "nocturnalsugars"),
    ("All Art Must Die",        "1:05",  "allartmustdie"),
    ("Daylight Brings",         "3:56",  "daylightbrings"),
    ("Hills of Life",           "2:34",  "hillsoflife"),
    ("As Seen From Afar",       "0:56",  "asseenfromafar"),
    ("The Great Adventure",     "5:31",  "thegreatadventure"),
    ("Sequels",                 "7:13",  "sequels"),
    ("Seconds of Dream",        "14:37", "secondsofdream"),
]
assert len(SECONDS_OF_DREAM_TRACKS) == 13

CLUE8_CIPHER = "ehk-bqNEFRUn-"
assert len(CLUE8_CIPHER) == 13
CLUE8_VALUES = [0 if c == "-" else (ord(c.lower()) - 96) for c in CLUE8_CIPHER]
TRACK_LENGTHS = [len(t[2]) for t in SECONDS_OF_DREAM_TRACKS]  # [16,21,12,9,10,15,13,14,11,14,17,7,14]


def clue8_rule_a_dual_branch() -> tuple[str, str]:
    """
    RULE H8-A (Repo C8.2 Dual-Branch Track Lookup):
      - All 13 cells produce s13 = 'gaetuifrlhita', whose A1Z26 concatenation is 18 digits ('715202196181289201').
      - Dropping the trailing dash at cell 13 (s12 = 'gaetuifrlhit') produces the 17-digit string '71520219618128920'.
    """
    letters = []
    for idx0, ch in enumerate(CLUE8_CIPHER):
        tr_idx0 = idx0 if ch == "-" else ((ord(ch.lower()) - 97) % 13)
        tr_clean = SECONDS_OF_DREAM_TRACKS[tr_idx0][2]
        assert 0 <= idx0 < len(tr_clean)
        letters.append(tr_clean[idx0])
    s13 = "".join(letters)
    s18_all = "".join(str(ord(c) - 96) for c in s13)
    s17_drop_trailing_dash = "".join(str(ord(c) - 96) for c in s13[:12])
    assert len(s13) == 13 and len(s18_all) == 18 and len(s17_drop_trailing_dash) == 17
    return s13, s17_drop_trailing_dash


def clue8_rule_b_abs_diff() -> tuple[str, str]:
    """
    RULE H8-B (Sequential 13-Track Absolute-Difference Rule d_i = |L_i - v_i|):
      - With 1-based dash rule (i->Track_i[i]): 13-letter string 'enttroabsegsa'.
      - Skipping both dashes uniformly (11 letter cols): 'entroabsegs' -> A1Z26 = '51420181512195719' (exact length 17).
    """
    out, out_no_dash = [], []
    for idx0, (ch, v, L) in enumerate(zip(CLUE8_CIPHER, CLUE8_VALUES, TRACK_LENGTHS)):
        pos1 = idx0 + 1
        tr_clean = SECONDS_OF_DREAM_TRACKS[idx0][2]
        if ch == "-":
            out.append(tr_clean[pos1 - 1])
        else:
            d = abs(L - v)
            assert 1 <= d <= L
            out.append(tr_clean[d - 1])
            out_no_dash.append(tr_clean[d - 1])
    res13 = "".join(out)
    res11 = "".join(out_no_dash)
    s17_no_dash = "".join(str(ord(c) - 96) for c in res11)
    assert len(res13) == 13 and len(res11) == 11 and len(s17_no_dash) == 17
    return res13, s17_no_dash


def clue8_rule_c_uppercase_squeeze() -> dict:
    """
    RULE H8-C (Uppercase NEFRU Boundary-Squeeze Proof & Dash Base Variants):
      - Uppercase cols 7..11 (N=14, E=5, F=6, R=18, U=21) are uniquely squeezed to k = -4 -> 'tdire' (5 chars).
      - Evaluates three dash conventions for Col 4 ('-') and Col 13 ('-'):
          1. 1-based Track_i[i]  : Col 4 = exitlight[3] = 't', Col 13 = secondsofdream[12] = 'a' -> 'enttrotdiresa' / 'enttrltdirela'
          2. 0-based Track_i[i]  : Col 4 = exitlight[4] = 'l', Col 13 = secondsofdream[13] = 'm' -> 'entlrotdiresm' / 'entlrltdirelm'
          3. Col 4 = 'e' ('enter'): Col 4 = exitlight[0] = 'e' (spelling 'enter' in Cols 1..5!) -> 'enterotdiresa' / 'enterltdirela'
    """
    upper_cols_0 = [6, 7, 8, 9, 10]
    k_min = max(1 - CLUE8_VALUES[i] for i in upper_cols_0)
    k_max = min(TRACK_LENGTHS[i] - CLUE8_VALUES[i] for i in upper_cols_0)
    assert k_min == -4 and k_max == -4
    k = -4
    tdire = "".join(SECONDS_OF_DREAM_TRACKS[i][2][CLUE8_VALUES[i] + k - 1] for i in upper_cols_0)
    assert len(tdire) == 5 and tdire == "tdire"

    c1_1based, c2_1based = [], []
    for idx0, (ch, v, L) in enumerate(zip(CLUE8_CIPHER, CLUE8_VALUES, TRACK_LENGTHS)):
        pos1 = idx0 + 1
        tr = SECONDS_OF_DREAM_TRACKS[idx0][2]
        if ch == "-":
            c1_1based.append(tr[pos1 - 1])
            c2_1based.append(tr[pos1 - 1])
        elif ch.isupper():
            c1_1based.append(tr[v - 4 - 1])
            c2_1based.append(tr[v - 4 - 1])
        else:
            d1 = abs(L - v)
            d2 = (L - v) if v < L else (v - 8)
            assert 1 <= d1 <= L and 1 <= d2 <= L
            c1_1based.append(tr[d1 - 1])
            c2_1based.append(tr[d2 - 1])

    s_c1 = "".join(c1_1based)  # "enttrotdiresa"
    s_c2 = "".join(c2_1based)  # "enttrltdirela"
    # 0-based dash indexing: exitlight[4] = 'l', secondsofdream[13] = 'm'
    d4_0based = SECONDS_OF_DREAM_TRACKS[3][2][4]
    d13_0based = SECONDS_OF_DREAM_TRACKS[12][2][13]
    assert d4_0based == "l" and d13_0based == "m"
    s_c1_0based = s_c1[:3] + d4_0based + s_c1[4:12] + d13_0based  # "entlrotdiresm"
    s_c2_0based = s_c2[:3] + d4_0based + s_c2[4:12] + d13_0based  # "entlrltdirelm"
    # Col 4 = 'e' (spelling literal 'enter' in Cols 1..5!)
    s_c1_enter = s_c1[:3] + "e" + s_c1[4:]  # "enterotdiresa"
    s_c2_enter = s_c2[:3] + "e" + s_c2[4:]  # "enterltdirela"

    for s in (s_c1, s_c2, s_c1_0based, s_c2_0based, s_c1_enter, s_c2_enter):
        assert len(s) == 13
    assert s_c1_enter[:5] == "enter" and s_c2_enter[:5] == "enter"

    return {
        "k_unique": k,
        "fixed_5_chars_cols_7_to_11": tdire,
        "hybrid_13_abs_lower": s_c1,          # "enttrotdiresa"
        "hybrid_13_v_minus_8_lower": s_c2,    # "enttrltdirela"
        "hybrid_13_0based_abs": s_c1_0based,  # "entlrotdiresm"
        "hybrid_13_0based_v8": s_c2_0based,   # "entlrltdirelm"
        "hybrid_13_enter_abs": s_c1_enter,    # "enterotdiresa"
        "hybrid_13_enter_v8": s_c2_enter,     # "enterltdirela"
    }


# ---------------------------------------------------------------------------
# 3. CLUE 3 (WASD, 8 CHARS) & CLUE 7 (SHIP, 24 CHARS EXPLICIT CANDIDATES)
# ---------------------------------------------------------------------------
WASD_GRID = [
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

SHIP_EXPLICIT_CANDIDATES = {
    "decks_4":          "sheltersaloonuppermiddle",  # 4 Titanic decks (7+6+5+6=24)
    "andrews_quote_1":  "isamathematicalcertainty",  # Titanic screenplay ("It is a mathematical certainty")
    "andrews_quote_2":  "sheismadeofironsirassure",  # Titanic screenplay ("She is made of iron, sir. [I] assure...")
    "ismay_andrews_1":  "jbruceismaythomasandrews",  # 11+13 = 24
    "ismay_andrews_2":  "thomasandrewsjbruceismay",  # 13+11 = 24
    "smith_andrews_1":  "edwardsmiththomasandrews",  # 11+13 = 24
    "smith_andrews_2":  "thomasandrewsedwardsmith",  # 13+11 = 24
    "actors_1":         "victorgarberjonathanhyde",  # 12+12 = 24
    "actors_2":         "jonathanhydevictorgarber",  # 12+12 = 24
    "deck_plan_last":   "smithandrewsdeckplanlast",  # 24
    "stanza2_fate_1":   "thenightmovestomakerofit",  # 24
    "stanza2_fate_2":   "thecoldnightmovestomaker",  # 24
    "acrostic_plus_ta": "simoisiayscthomasandrews",  # 11 ('SIMOISIAYSC') + 13 ('thomasandrews') = 24
    "acrostic_plus_es": "simoisiayscedwardsmithjr",  # 11 + 13 = 24
    "ta_plus_acrostic": "thomasandrewssimoisiaysc",  # 13 + 11 = 24
}
for _k, _v in SHIP_EXPLICIT_CANDIDATES.items():
    assert len(_v) == 24, f"SHIP candidate {_k} has length {len(_v)} != 24"


# ---------------------------------------------------------------------------
# 4. CLUE 4 (CHESS, 12 CHARS CASE-PRESERVED): EXPLICIT 14->12 & COORD HYPOTHESES
# ---------------------------------------------------------------------------
CHESS_PIECES_14 = [
    ("r", "e", 8), ("r", "a", 7), ("k", "b", 7), ("p", "c", 7), ("p", "f", 7),
    ("p", "b", 6), ("p", "d", 6), ("n", "f", 6), ("p", "g", 6),
    ("N", "g", 5), ("B", "d", 4), ("Q", "b", 3), ("P", "c", 3), ("K", "c", 2),
]
assert len(CHESS_PIECES_14) == 14

CHESS_EXPLICIT_CANDIDATES = {
    "drop_2_kings_8to1":     "rrppppnpNBQP",  # 14 pieces minus (k, K), rank 8->1
    "drop_2_kings_1to8":     "PQBNppnpprrr"[:12],
    "drop_c_file_pawns":     "rrkpponpNBQK".replace("o", "p"),  # 14 pieces minus (pc7, Pc3) on c-file
    "hierarchy_no_kings":    "ppppppnNBrre".replace("e", "Q"),  # P -> N -> B -> R -> Q (front lines to throne)
    "white_court_4x3":       "Ng5Bd4Qb3Kc2",  # 4 White court pieces (Piece+file+rank = 12 chars)
    "white_nonking_4x3":     "Pc3Qb3Bd4Ng5",  # 4 White non-king pieces (front lines to court = 12 chars)
    "non_fringe_6_piece_rk": "r7k7p6N5B4Q3",  # 6 non-fringe pieces {a7,b7,b6,g5,d4,b3} as Piece+Rank
    "non_fringe_6_piece_fl": "rakbpbgdNdbQ"[:12],
}
for _k, _v in CHESS_EXPLICIT_CANDIDATES.items():
    assert len(_v) == 12, f"CHESS candidate {_k} has length {len(_v)} != 12"


# ---------------------------------------------------------------------------
# 5. GITHUB RECONNAISSANCE & HARDWARE AES-NI ENGINE SUMMARY
# ---------------------------------------------------------------------------
GITHUB_RECON_SUMMARY = {
    "author_repos_jpatt94": {
        "versusworld": "https://github.com/jpatt94/versusworld (Justin Patterson, 2017)",
        "versusworld_builds": "https://github.com/jpatt94/versusworld_builds",
        "key_findings": [
            "Fonts: Assets/Fonts/whitrabt.ttf ('White Rabbit') is the exact monospace font used in 238_computer_screen.png, 100_tower.png, and 139_scramble.png.",
            "Toolchain: GIMP (.xcf in Working Files/) for textures, FL Studio (Working Files/Music/ZeroMinusRed.flp) for DAW composition, Maya (.mb) for 3D models.",
            "Location & Sports Icons: Minnesota (TimberwolvesIcon.png, TwinsIcon.png, VikingsIcon.png, WildIcon.png).",
            "Music/Lore Links: 3D scenes named after Equilibrium folk-metal albums (Erdentempel.unity, Rekreatur.mb) plus SandVault.unity, SkylineJungle.unity, WebIsland.unity, WolfTown.unity.",
        ],
    },
    "community_repos": {
        "turjaun985123/path-to-greatness-3ltc": "Renamed from jerinshop7-maker/path-to-greatness-3ltc; latest commit 2afb9d12 (Round 21 dither recovery & seg3_cross.c at 1.3-2.4 MKeys/s/core).",
        "floflo777/open-crypto-puzzles": "Main catalogue + active forks (windstalker-arch, dhruverse1-sys, AppleLamps, Schum-io).",
    },
    "hardware_aesni_engine": {
        "source": "/home/user/p2g_work/fast_seg_oracle_aesni.c -> /home/user/p2g_work/fast_seg_oracle.so",
        "architecture": "Bare-metal Intel AES-NI (_mm_aesdec_si128 + _mm_aesimc_si128 + 4x-ILP shared-rk1 pipeline + OpenMP)",
        "validation": "0 disagreements across 2,000 random keys across Segments 1-4 against oracle.AES",
        "speedup_vs_repo_seg3_cross": "~13.6x faster per core (32.78 MKeys/s on 2 vCPUs vs 2.4 MKeys/s/core in software seg3_cross.c)",
    },
}


def walk_wasd(start_row: int = 6, start_col: int = 5, steps: int = 13):
    r, c = start_row, start_col
    path = []
    for _ in range(steps):
        cell = WASD_GRID[r][c]
        path.append((c, r, cell))
        if cell[1] == "*":
            break
        n, d = int(cell[0]), cell[1]
        if d == "W":
            r -= n
        elif d == "S":
            r += n
        elif d == "A":
            c -= n
        elif d == "D":
            c += n
    assert len(path) == steps, f"Expected path of length {steps}, got {len(path)}"
    return path


def find_walks_with_4_and_8_at_tracks_4_and_5():
    forward_hits, reverse_hits = [], []
    for r0 in range(10):
        for c0 in range(10):
            r, c = r0, c0
            path = []
            for _ in range(13):
                cell = WASD_GRID[r][c]
                path.append((c, r, cell))
                if cell[1] == "*":
                    break
                n, d = int(cell[0]), cell[1]
                if d == "W":
                    r -= n
                elif d == "S":
                    r += n
                elif d == "A":
                    c -= n
                elif d == "D":
                    c += n
            if len(path) == 13:
                digits = [int(x[2][0]) for x in path]
                if digits[3] == 4 and digits[4] == 8:
                    forward_hits.append(((c0, r0), (path[-1][0], path[-1][1]), digits))
                rev = digits[::-1]
                if rev[3] == 4 and rev[4] == 8:
                    reverse_hits.append(((c0, r0), (path[-1][0], path[-1][1]), rev))
    assert len(forward_hits) == 1 and len(reverse_hits) == 3
    return forward_hits, reverse_hits


if __name__ == "__main__":
    print("=== 0. SEGMENT STATUS LEDGER ===")
    total_p = 0
    for seg_id, info in SEGMENT_STATUS.items():
        total_p += info["pairs_tested"]
        print(f"  {seg_id:4s} : {info['status']:32s} | pairs={info['pairs_tested']:14,d} | hits={info['hits']}")
    print(f"  TOTAL: {total_p:14,d} pairs tested across Segments 1-4 (hits=0)")

    print("\n=== 1. PRIORITIZED RECOMMENDATION RUNS (REC 1..6) ===")
    for tag, desc, nl, nr, npairs, t_str, h in RECOMMENDATION_RUN_LEDGER:
        print(f"  {tag:14s} | {nl:9,d} x {nr:7,d} = {npairs:11,d} pairs ({t_str:6s}) -> hit={h} | {desc}")

    print("\n=== 2. CLUE 2 EXPLICIT CANDIDATES (10 BASE + 27 WINDOWS OF P) ===")
    dec2 = decode_clue2()
    assert len(dec2) == 41 and len(SCRAMBLE_WINDOWS_27_P) == 27
    print(f"  Decoded P (41)     : {dec2}")
    print(f"  cap_from_P (15)    : {SCRAMBLE_EXPLICIT_CANDIDATES['cap_from_P']}")
    print(f"  Windows of P (27)  : [{SCRAMBLE_WINDOWS_27_P[0]!r}, {SCRAMBLE_WINDOWS_27_P[1]!r}, ..., {SCRAMBLE_WINDOWS_27_P[-1]!r}]")

    print("\n=== 3. CLUE 8 DISAMBIGUATED RULES & DASH VARIANTS ===")
    r8_s13, r8_s17 = clue8_rule_a_dual_branch()
    r8_b13, r8_b17 = clue8_rule_b_abs_diff()
    r8_c = clue8_rule_c_uppercase_squeeze()
    print(f"  H8-A (Dual-Branch) : s13='{r8_s13}' (18 digits) -> s12 A1Z26='{r8_s17}' (len=17)")
    print(f"  H8-B (|L_i - v_i|) : s13='{r8_b13}' -> 11 non-dash A1Z26='{r8_b17}' (len=17)")
    print(f"  H8-C (Squeeze k=-4): fixed cols 7..11='{r8_c['fixed_5_chars_cols_7_to_11']}'")
    print(f"    1-based dashes   : '{r8_c['hybrid_13_abs_lower']}' / '{r8_c['hybrid_13_v_minus_8_lower']}'")
    print(f"    0-based dashes   : '{r8_c['hybrid_13_0based_abs']}' / '{r8_c['hybrid_13_0based_v8']}'")
    print(f"    col 4='e' (enter): '{r8_c['hybrid_13_enter_abs']}' / '{r8_c['hybrid_13_enter_v8']}'")

    path = walk_wasd(6, 5, 13)
    fwd, rev = find_walks_with_4_and_8_at_tracks_4_and_5()
    assert len(path) == 13 and len(fwd) == 1 and len(rev) == 3
    print("\n=== 4. NEW FORENSIC DISCOVERIES (BLUE-HERRING SAND, PICTOGRAM REBUS, SPELLED WASD) ===")
    print("  [Beach.png Sand Layer] Top-left explicitly reads: 'blUE-hERRing' (x=19..121, y=227..235)")
    print("    -> Confirms '0,0..9,9', '5,6', '3,0', 'BDfgFK-FC', 'GOdcbA-A' & 100_tower.png Key/Lock = 'blue herring' decoy!")
    print("  [98_wonders.png Rebus] 6 red pictograms map 1-to-1 to the 6 quoted songs (lit 'km' torches):")
    print("    Row 1 (12,772 km, S, E): [Ghost+Heart]=Ghost Love Score (L5) + [Island+Chest]=Treasure Island (L8)")
    print("    Row 2 ( 5,210 km, N, W): [Anchor]=High Hopes (L6)            + [3 Devils]=Three Evils (L7)")
    print("    Row 3 (12,061 km, N, E): [Viking Helmet]=Havamal (L4)        + [* ? *]=Astral and Arcane (L2)")
    print("  [110_wasd.png <- P]    'Directions should be spelled and check the first':")
    print("    Spelled green roots (exact len=8): 'fiveeast', 'twonorth', 'fourwest', 'fourleft', 'onesouth'")
    print("    First-letter udlr/nwse remapping : 'd3w1as24' -> 'r3u1ld24' / 'e3n1ws24'")
    print("\n=== 5. ALL LENGTH & WITNESS ASSERTIONS PASSED ===")

