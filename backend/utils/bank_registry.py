"""
AML Monitoring System — Swiss & German Bank Registry
Bank code → (name, BIC, city) lookup tables for IBAN resolution.

Switzerland: Uses 5-digit IID (Institut-Identifikation) from SIX Interbank Clearing
Germany:     Uses 8-digit BLZ (Bankleitzahl) from Bundesbank

Sources:
  - SIX Group: https://www.six-interbank-clearing.com/en/home/bank-master-data.html
  - Deutsche Bundesbank: https://www.bundesbank.de/de/aufgaben/unbarer-zahlungsverkehr/bankleitzahlen
  - FINMA regulated institutions list
  - BaFin licensed credit institutions list
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Switzerland — IID (Institut-Identifikation, 5 digits)
# Major FINMA-supervised institutions
# ---------------------------------------------------------------------------
SWISS_BANKS: dict[str, dict] = {
    # ── Big Banks (Grossbanken) ──────────────────────────────────────────────
    "00762": {"name": "UBS Switzerland AG",              "bic": "UBSWCHZH80A", "city": "Zürich",     "category": "big_bank"},
    "00230": {"name": "Credit Suisse (Schweiz) AG",      "bic": "CRESCHZZ80A", "city": "Zürich",     "category": "big_bank"},
    "08390": {"name": "UBS Switzerland AG (Lugano)",     "bic": "UBSWCHZH20A", "city": "Lugano",     "category": "big_bank"},

    # ── Cantonal Banks (Kantonalbanken) ──────────────────────────────────────
    "70000": {"name": "Zürcher Kantonalbank (ZKB)",      "bic": "ZKBKCHZZ80A", "city": "Zürich",     "category": "cantonal"},
    "76000": {"name": "Berner Kantonalbank (BEKB)",      "bic": "BEKCCH22XXX", "city": "Bern",       "category": "cantonal"},
    "76400": {"name": "Basler Kantonalbank",              "bic": "BKBBCHBBXXX", "city": "Basel",      "category": "cantonal"},
    "78000": {"name": "Basellandschaftliche Kantonalbank","bic": "BLKBCH22XXX", "city": "Liestal",    "category": "cantonal"},
    "79000": {"name": "St. Galler Kantonalbank",         "bic": "SGKBCH22XXX", "city": "St. Gallen", "category": "cantonal"},
    "80000": {"name": "Aargauische Kantonalbank (AKB)",  "bic": "AGRICHED1XXX", "city": "Aarau",     "category": "cantonal"},
    "65000": {"name": "Banque Cantonale de Genève (BCGE)","bic": "BCGECHGGXXX", "city": "Genf",      "category": "cantonal"},
    "64000": {"name": "Banque Cantonale Vaudoise (BCV)", "bic": "BCVLCH2LXXX", "city": "Lausanne",   "category": "cantonal"},
    "56000": {"name": "Luzerner Kantonalbank (LUKB)",    "bic": "LUKBCH2260A", "city": "Luzern",     "category": "cantonal"},
    "83000": {"name": "Thurgauer Kantonalbank (TKB)",    "bic": "KBTGCH22XXX", "city": "Weinfelden", "category": "cantonal"},

    # ── Raiffeisen Group ─────────────────────────────────────────────────────
    "80808": {"name": "Raiffeisen Schweiz (Zentrale)",   "bic": "RAIFCH22XXX", "city": "St. Gallen", "category": "cooperative"},
    "80080": {"name": "Raiffeisen Zürich",               "bic": "RAIFCH22ZUR", "city": "Zürich",     "category": "cooperative"},

    # ── PostFinance ──────────────────────────────────────────────────────────
    "09000": {"name": "PostFinance AG",                  "bic": "POFICHBEXXX", "city": "Bern",       "category": "post"},

    # ── Private Banks (Privatbanken) ─────────────────────────────────────────
    "08780": {"name": "Julius Bär & Co. AG",             "bic": "BSLJCHZZXXX", "city": "Zürich",     "category": "private"},
    "08480": {"name": "Pictet & Cie (Europe) SA",        "bic": "PICTCHGGXXX", "city": "Genf",       "category": "private"},
    "08810": {"name": "Lombard Odier & Cie",             "bic": "LOCYCHGGXXX", "city": "Genf",       "category": "private"},
    "08530": {"name": "J. Safra Sarasin AG",             "bic": "BSLBCHBBXXX", "city": "Basel",      "category": "private"},
    "08800": {"name": "Vontobel AG",                     "bic": "VONTCHZZXXX", "city": "Zürich",     "category": "private"},
    "08650": {"name": "EFG International AG",            "bic": "EFGBCHZZXXX", "city": "Zürich",     "category": "private"},

    # ── Foreign Banks (Switzerland) ──────────────────────────────────────────
    "07920": {"name": "Deutsche Bank (Schweiz) AG",      "bic": "DEUTCHZZXXX", "city": "Zürich",     "category": "foreign"},
    "07810": {"name": "Citibank N.A. (Zürich)",          "bic": "CITICHZZXXX", "city": "Zürich",     "category": "foreign"},
    "07860": {"name": "HSBC Private Bank (Suisse) SA",   "bic": "HSBCCHGGXXX", "city": "Genf",       "category": "foreign"},

    # ── Neo / Challenger Banks ───────────────────────────────────────────────
    "09400": {"name": "Neon Money Club AG",              "bic": "NEOMCHZZXXX", "city": "Zürich",     "category": "digital"},
    "09500": {"name": "Yuh (Swissquote/PostFinance)",    "bic": "SWQBCHZZXXX", "city": "Gland",      "category": "digital"},
}


# ---------------------------------------------------------------------------
# Germany — BLZ (Bankleitzahl, 8 digits)
# Major BaFin-supervised institutions
# ---------------------------------------------------------------------------
GERMAN_BANKS: dict[str, dict] = {
    # ── Deutsche Bank Group ──────────────────────────────────────────────────
    "37070024": {"name": "Deutsche Bank AG",             "bic": "DEUTDEDBXXX", "city": "Frankfurt am Main", "category": "big_bank"},
    "20070024": {"name": "Deutsche Bank Hamburg",        "bic": "DEUTDEHHXXX", "city": "Hamburg",           "category": "big_bank"},
    "70070010": {"name": "Deutsche Bank München",        "bic": "DEUTDEMUXXX", "city": "München",           "category": "big_bank"},

    # ── Commerzbank Group ────────────────────────────────────────────────────
    "20040000": {"name": "Commerzbank AG (Hamburg)",     "bic": "COBADEHHXXX", "city": "Hamburg",           "category": "big_bank"},
    "37040044": {"name": "Commerzbank AG (Frankfurt)",   "bic": "COBADEFFXXX", "city": "Frankfurt am Main", "category": "big_bank"},
    "70040041": {"name": "Commerzbank AG (München)",     "bic": "COBADEMUXXX", "city": "München",           "category": "big_bank"},

    # ── Sparkassen-Finanzgruppe ──────────────────────────────────────────────
    "10050000": {"name": "Berliner Sparkasse",           "bic": "BELADEBEXXX", "city": "Berlin",            "category": "savings"},
    "20050550": {"name": "Hamburger Sparkasse (Haspa)",  "bic": "HASPDEHHXXX", "city": "Hamburg",           "category": "savings"},
    "36050105": {"name": "Sparkasse KölnBonn",           "bic": "COLSDE33XXX", "city": "Köln",              "category": "savings"},
    "70150000": {"name": "Stadtsparkasse München",       "bic": "SSKMDEMMXXX", "city": "München",           "category": "savings"},
    "25050180": {"name": "Sparkasse Hannover",           "bic": "SPKHDE2HXXX", "city": "Hannover",          "category": "savings"},
    "30050110": {"name": "Stadtsparkasse Düsseldorf",    "bic": "DUSSDEDDXXX", "city": "Düsseldorf",        "category": "savings"},

    # ── DZ Bank Group / Volksbanken ──────────────────────────────────────────
    "50060400": {"name": "DZ BANK AG",                   "bic": "GENODEFFXXX", "city": "Frankfurt am Main", "category": "cooperative"},
    "10090000": {"name": "Berliner Volksbank eG",        "bic": "BEVODEBEXXX", "city": "Berlin",            "category": "cooperative"},
    "70090100": {"name": "Münchner Bank eG",             "bic": "GENODEF1M04", "city": "München",           "category": "cooperative"},

    # ── KfW / Development Banks ──────────────────────────────────────────────
    "50020200": {"name": "KfW Bankengruppe",             "bic": "KFWIDEFFXXX", "city": "Frankfurt am Main", "category": "development"},

    # ── Landesbanken ─────────────────────────────────────────────────────────
    "20050000": {"name": "HSH Nordbank AG",              "bic": "HSHNDEHH",   "city": "Hamburg",           "category": "landbank"},
    "70050000": {"name": "BayernLB",                     "bic": "BYLADEMM",   "city": "München",           "category": "landbank"},
    "30020900": {"name": "NRW.BANK",                     "bic": "NRWBDEDAXXX","city": "Düsseldorf",        "category": "landbank"},

    # ── Private / Investment Banks ───────────────────────────────────────────
    "50120383": {"name": "Goldman Sachs Bank Europe SE", "bic": "GOLDDEFFFXXX","city": "Frankfurt am Main", "category": "investment"},
    "50110800": {"name": "J.P. Morgan AG",               "bic": "CHASDEFXXXX","city": "Frankfurt am Main", "category": "investment"},
    "20030000": {"name": "Berenberg Bank",               "bic": "BERBDEHHXXX","city": "Hamburg",           "category": "private"},

    # ── Digital / Challenger ─────────────────────────────────────────────────
    "10011001": {"name": "N26 Bank GmbH",                "bic": "NTSBDEB1XXX","city": "Berlin",            "category": "digital"},
    "30030700": {"name": "Penta (Qonto Deutschland)",    "bic": "QNTODEM1XXX","city": "Berlin",            "category": "digital"},
    "20030600": {"name": "Solaris SE",                   "bic": "SOBKDEBBXXX","city": "Berlin",            "category": "digital"},
}


# ---------------------------------------------------------------------------
# Austria — Bankleitzahl (5 digits)
# ---------------------------------------------------------------------------
AUSTRIAN_BANKS: dict[str, dict] = {
    "12000": {"name": "UniCredit Bank Austria AG",       "bic": "BKAUATWWXXX", "city": "Wien",   "category": "big_bank"},
    "20111": {"name": "Erste Bank der oesterr. Sparkassen", "bic": "GIBAATWWXXX", "city": "Wien", "category": "savings"},
    "43000": {"name": "Raiffeisen Bank International AG","bic": "RZBAATWWXXX", "city": "Wien",   "category": "cooperative"},
    "14000": {"name": "Raiffeisenlandesbank NÖ-Wien",   "bic": "RLNWATWWXXX", "city": "Wien",   "category": "cooperative"},
    "20815": {"name": "BAWAG P.S.K. AG",                 "bic": "BAWAATWWXXX", "city": "Wien",   "category": "big_bank"},
    "32000": {"name": "Volksbank Wien AG",               "bic": "VBOEATWWXXX", "city": "Wien",   "category": "cooperative"},
    "19190": {"name": "Oberbank AG",                     "bic": "OBKLAT2LXXX", "city": "Linz",   "category": "regional"},
    "57000": {"name": "Hypo Vorarlberg Bank AG",         "bic": "HYPVAT2BXXX", "city": "Bregenz","category": "regional"},
}


# ---------------------------------------------------------------------------
# Convenience lookups
# ---------------------------------------------------------------------------
def lookup_bank(iban_normalized: str) -> Optional[dict]:
    """Return bank metadata for a normalized IBAN, or None."""
    cc = iban_normalized[:2]
    registry = {
        "CH": (SWISS_BANKS, 4, 9),
        "DE": (GERMAN_BANKS, 4, 12),
        "AT": (AUSTRIAN_BANKS, 4, 9),
    }.get(cc)
    if not registry:
        return None
    banks, start, end = registry
    return banks.get(iban_normalized[start:end])


def get_bic(iban_normalized: str) -> Optional[str]:
    info = lookup_bank(iban_normalized)
    return info.get("bic") if info else None
