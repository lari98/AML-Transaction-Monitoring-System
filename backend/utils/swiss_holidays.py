"""
AML Monitoring System — Swiss & German Bank Holiday Calendar
Covers all 26 Swiss cantons (focus: ZH, GE, BS, BE, LU, VD, AG, SG, TG, TI)
and all 16 German federal states (Bundesländer).

Used by AnomalyDetector._is_bank_holiday() for accurate CH/DE coverage.

Compliance references:
- Swiss: Obligationenrecht Art. 299 + cantonal laws
- German: Feiertagsgesetze der Länder (16 state laws)
- Financial markets: SIX Swiss Exchange / Deutsche Börse non-trading days
"""
from __future__ import annotations

from datetime import date, timedelta
from functools import lru_cache
from typing import Optional, Set


# ── Easter Computation (Gauss Algorithm) ──────────────────────────────────────

def _easter(year: int) -> date:
    """Compute Easter Sunday via the anonymous Gregorian algorithm."""
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(year, month, day)


def _easter_offsets(year: int) -> dict[str, date]:
    """Pre-compute all Easter-relative holidays for a given year."""
    e = _easter(year)
    return {
        "good_friday":       e - timedelta(days=2),
        "easter_sunday":     e,
        "easter_monday":     e + timedelta(days=1),
        "ascension":         e + timedelta(days=39),
        "whit_sunday":       e + timedelta(days=49),
        "whit_monday":       e + timedelta(days=50),
        "corpus_christi":    e + timedelta(days=60),
    }


# ── Swiss Holiday Calendar ────────────────────────────────────────────────────

# Fixed national holidays (all cantons)
_CH_NATIONAL_FIXED = {
    (1, 1):   "Neujahrstag / Jour de l'An",
    (8, 1):   "Bundesfeiertag / Fête nationale",
    (12, 25): "Weihnachten / Noël",
}

# Fixed holidays per canton — set of (month, day)
_CH_CANTON_FIXED: dict[str, set[tuple[int, int]]] = {
    # Zürich (ZH) — financial center
    "ZH": {(1, 2), (5, 1), (12, 26)},
    # Bern (BE) — federal capital
    "BE": {(1, 2), (12, 26)},
    # Luzern (LU)
    "LU": {(1, 2), (1, 6), (3, 19), (5, 1), (6, 29), (8, 15), (11, 1), (12, 8), (12, 26)},
    # Basel-Stadt (BS) — bank hub
    "BS": {(1, 2), (5, 1), (12, 26)},
    # Genf/Geneva (GE) — private banking hub
    "GE": {(1, 2), (12, 31)},
    # Waadt/Vaud (VD) — Lausanne
    "VD": {(1, 2), (12, 26)},
    # Aargau (AG)
    "AG": {(1, 6), (5, 1), (8, 15), (11, 1), (12, 8), (12, 26)},
    # Thurgau (TG)
    "TG": {(1, 2), (5, 1), (12, 26)},
    # St. Gallen (SG)
    "SG": {(1, 6), (5, 1), (6, 29), (8, 15), (11, 1), (12, 26)},
    # Tessin/Ticino (TI) — cross-border with Italy
    "TI": {(1, 6), (3, 19), (5, 1), (6, 24), (6, 29), (8, 15), (11, 1), (12, 8), (12, 26)},
    # Wallis/Valais (VS)
    "VS": {(1, 6), (3, 19), (5, 1), (6, 29), (7, 25), (8, 15), (11, 1), (12, 8), (12, 26)},
    # Graubünden (GR)
    "GR": {(1, 6), (3, 9), (12, 26)},
    # Solothurn (SO)
    "SO": {(1, 2), (5, 1), (12, 26)},
    # Schaffhausen (SH)
    "SH": {(1, 2), (5, 1), (12, 26)},
    # Fribourg (FR)
    "FR": {(1, 2), (5, 1), (8, 15), (11, 1), (12, 8), (12, 26)},
    # Neuchâtel (NE)
    "NE": {(3, 1), (12, 26)},
    # Jura (JU)
    "JU": {(1, 2), (5, 1), (8, 15), (11, 1), (12, 26)},
}

# Easter-relative holidays per canton
_CH_CANTON_EASTER: dict[str, set[str]] = {
    "ZH": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "BE": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "LU": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "BS": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "GE": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "VD": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "AG": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "TG": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "SG": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "TI": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "VS": {"easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "GR": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "SO": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "SH": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "FR": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
    "NE": {"good_friday", "easter_monday", "ascension", "whit_monday"},
    "JU": {"good_friday", "easter_monday", "ascension", "corpus_christi", "whit_monday"},
}

# Default (national average) for unknown cantons
_CH_CANTON_FIXED.setdefault("DEFAULT", {(1, 2), (12, 26)})
_CH_CANTON_EASTER.setdefault("DEFAULT", {"good_friday", "easter_monday", "ascension", "whit_monday"})


@lru_cache(maxsize=128)
def get_swiss_holidays(year: int, canton: str = "ZH") -> frozenset[date]:
    """
    Return all Swiss public holidays for a given year and canton.

    Args:
        year:   Calendar year
        canton: Two-letter Swiss canton code (ZH, BE, BS, GE, LU, VD, AG, TG, SG, TI, …)

    Returns:
        frozenset of date objects (cached for performance)
    """
    canton = canton.upper()
    holidays: set[date] = set()

    # National fixed holidays
    for (month, day), _ in _CH_NATIONAL_FIXED.items():
        holidays.add(date(year, month, day))

    # Canton-specific fixed
    canton_fixed = _CH_CANTON_FIXED.get(canton, _CH_CANTON_FIXED["DEFAULT"])
    for month, day in canton_fixed:
        try:
            holidays.add(date(year, month, day))
        except ValueError:
            pass  # e.g. Feb 29 in non-leap years

    # Easter-relative
    easter_dates = _easter_offsets(year)
    canton_easter = _CH_CANTON_EASTER.get(canton, _CH_CANTON_EASTER["DEFAULT"])
    for key in canton_easter:
        if key in easter_dates:
            holidays.add(easter_dates[key])

    return frozenset(holidays)


# ── German Holiday Calendar ───────────────────────────────────────────────────

# German federal (all 16 states)
_DE_NATIONAL_FIXED = {
    (1, 1):   "Neujahrstag",
    (5, 1):   "Tag der Arbeit",
    (10, 3):  "Tag der Deutschen Einheit",
    (12, 25): "1. Weihnachtstag",
    (12, 26): "2. Weihnachtstag",
}

_DE_NATIONAL_EASTER = {"good_friday", "easter_monday", "ascension", "whit_monday"}

# State-specific fixed holidays — (month, day) tuples
_DE_STATE_FIXED: dict[str, set[tuple[int, int]]] = {
    "BB": {(10, 31)},                      # Brandenburg
    "MV": {(10, 31)},                      # Mecklenburg-Vorpommern
    "SN": {(10, 31)},                      # Sachsen
    "ST": {(10, 31)},                      # Sachsen-Anhalt
    "TH": {(10, 31)},                      # Thüringen
    "BY": {(1, 6), (8, 15), (11, 1), (12, 8)},  # Bayern
    "BW": {(1, 6), (11, 1)},               # Baden-Württemberg
    "NW": {(11, 1)},                       # Nordrhein-Westfalen
    "RP": {(11, 1)},                       # Rheinland-Pfalz
    "SL": {(11, 1)},                       # Saarland
    "HH": set(),                           # Hamburg
    "HB": set(),                           # Bremen
    "HE": set(),                           # Hessen
    "NI": set(),                           # Niedersachsen
    "SH": set(),                           # Schleswig-Holstein
    "BE": set(),                           # Berlin
}

_DE_STATE_EASTER: dict[str, set[str]] = {
    "BW": {"corpus_christi", "epiphany"},
    "BY": {"corpus_christi"},
    "HE": {"corpus_christi"},
    "NW": {"corpus_christi"},
    "RP": {"corpus_christi"},
    "SL": {"corpus_christi"},
    "SN": {"corpus_christi"},
    "TH": {"corpus_christi"},
    "BB": {"good_friday_extra"},  # Reformationstag handled as fixed
    "ST": set(),
    "MV": set(),
    "HH": set(),
    "HB": {"reformation_day_extra"},
    "NI": set(),
    "SH": set(),
    "HE": set(),
    "BE": set(),
}


@lru_cache(maxsize=128)
def get_german_holidays(year: int, state: str = "HE") -> frozenset[date]:
    """
    Return all German public holidays for a given year and federal state.

    Args:
        year:  Calendar year
        state: Two-letter German state code (HE, BY, BW, NW, BE, HH, …)

    Returns:
        frozenset of date objects
    """
    state = state.upper()
    holidays: set[date] = set()

    # National fixed
    for (month, day) in _DE_NATIONAL_FIXED:
        holidays.add(date(year, month, day))

    # National Easter-relative
    easter_dates = _easter_offsets(year)
    for key in _DE_NATIONAL_EASTER:
        if key in easter_dates:
            holidays.add(easter_dates[key])

    # State fixed
    for month, day in _DE_STATE_FIXED.get(state, set()):
        try:
            holidays.add(date(year, month, day))
        except ValueError:
            pass

    # State Easter-relative (corpus christi etc.)
    for key in _DE_STATE_EASTER.get(state, set()):
        if key in easter_dates:
            holidays.add(easter_dates[key])

    # Reformation Day for Lutheran states (Oct 31) — already in fixed for specific states
    # Add here for completeness check
    if state in {"BB", "MV", "SN", "ST", "TH", "HB", "SH", "HH"}:
        holidays.add(date(year, 10, 31))

    return frozenset(holidays)


# ── Deutsche Börse / SIX Exchange Non-Trading Days ───────────────────────────

_EXCHANGE_FIXED_CH = {(1, 1), (8, 1), (12, 25), (12, 26)}
_EXCHANGE_EASTER_CH = {"good_friday", "easter_monday"}

_EXCHANGE_FIXED_DE = {(1, 1), (5, 1), (10, 3), (12, 24), (12, 25), (12, 26), (12, 31)}
_EXCHANGE_EASTER_DE = {"good_friday", "easter_monday"}


@lru_cache(maxsize=64)
def get_exchange_holidays(year: int, exchange: str = "SIX") -> frozenset[date]:
    """
    Return non-trading days for SIX (Swiss) or XETRA/Frankfurt (German) exchange.

    Args:
        exchange: "SIX" for Swiss Exchange, "XETRA" or "FWB" for Frankfurt
    """
    easter_dates = _easter_offsets(year)
    holidays: set[date] = set()

    if exchange.upper() == "SIX":
        for m, d in _EXCHANGE_FIXED_CH:
            holidays.add(date(year, m, d))
        for key in _EXCHANGE_EASTER_CH:
            holidays.add(easter_dates[key])
    else:  # XETRA / FWB
        for m, d in _EXCHANGE_FIXED_DE:
            try:
                holidays.add(date(year, m, d))
            except ValueError:
                pass
        for key in _EXCHANGE_EASTER_DE:
            holidays.add(easter_dates[key])

    return frozenset(holidays)


# ── Unified Public API ────────────────────────────────────────────────────────

def is_bank_holiday(
    check_date: date,
    country: str = "CH",
    canton: Optional[str] = None,
    state: Optional[str] = None,
) -> bool:
    """
    Check if a given date is a public holiday in CH or DE.

    Args:
        check_date: The date to check
        country:    "CH" or "DE"
        canton:     Swiss canton code (ZH, BE, BS, GE, LU, VD, AG, TG, SG, TI, …)
                    Defaults to ZH (Zürich) for CH
        state:      German state code (HE, BY, BW, NW, BE, HH, …)
                    Defaults to HE (Hessen / Frankfurt) for DE

    Returns:
        True if the date is a public holiday in the specified jurisdiction
    """
    country = country.upper()

    if country == "CH":
        canton_code = (canton or "ZH").upper()
        return check_date in get_swiss_holidays(check_date.year, canton_code)

    elif country == "DE":
        state_code = (state or "HE").upper()
        return check_date in get_german_holidays(check_date.year, state_code)

    # Unknown country — fall back to major CH + DE combined
    return (
        check_date in get_swiss_holidays(check_date.year, "ZH")
        or check_date in get_german_holidays(check_date.year, "HE")
    )


def is_exchange_closed(check_date: date, exchange: str = "SIX") -> bool:
    """Check if a financial exchange is closed on a given date."""
    return check_date in get_exchange_holidays(check_date.year, exchange)


def is_business_day(check_date: date, country: str = "CH", canton: Optional[str] = None) -> bool:
    """Returns True if date is a business day (not weekend and not holiday)."""
    if check_date.weekday() >= 5:  # Saturday=5, Sunday=6
        return False
    return not is_bank_holiday(check_date, country=country, canton=canton)


def next_business_day(check_date: date, country: str = "CH", canton: Optional[str] = None) -> date:
    """Return the next business day after check_date."""
    d = check_date + timedelta(days=1)
    while not is_business_day(d, country=country, canton=canton):
        d += timedelta(days=1)
    return d


# ── Canton and State Metadata ─────────────────────────────────────────────────

SWISS_CANTONS = {
    "ZH": {"name_de": "Zürich",          "name_en": "Zurich",         "financial_center": True},
    "BE": {"name_de": "Bern",            "name_en": "Bern",           "financial_center": False},
    "LU": {"name_de": "Luzern",          "name_en": "Lucerne",        "financial_center": False},
    "UR": {"name_de": "Uri",             "name_en": "Uri",            "financial_center": False},
    "SZ": {"name_de": "Schwyz",          "name_en": "Schwyz",         "financial_center": False},
    "OW": {"name_de": "Obwalden",        "name_en": "Obwalden",       "financial_center": False},
    "NW": {"name_de": "Nidwalden",       "name_en": "Nidwalden",      "financial_center": False},
    "GL": {"name_de": "Glarus",          "name_en": "Glarus",         "financial_center": False},
    "ZG": {"name_de": "Zug",             "name_en": "Zug",            "financial_center": True},
    "FR": {"name_de": "Fribourg",        "name_en": "Fribourg",       "financial_center": False},
    "SO": {"name_de": "Solothurn",       "name_en": "Solothurn",      "financial_center": False},
    "BS": {"name_de": "Basel-Stadt",     "name_en": "Basel-City",     "financial_center": True},
    "BL": {"name_de": "Basel-Landschaft","name_en": "Basel-Country",  "financial_center": False},
    "SH": {"name_de": "Schaffhausen",    "name_en": "Schaffhausen",   "financial_center": False},
    "AR": {"name_de": "Appenzell AR",    "name_en": "Appenzell OR",   "financial_center": False},
    "AI": {"name_de": "Appenzell AI",    "name_en": "Appenzell IR",   "financial_center": False},
    "SG": {"name_de": "St. Gallen",      "name_en": "St. Gallen",     "financial_center": False},
    "GR": {"name_de": "Graubünden",      "name_en": "Graubünden",     "financial_center": False},
    "AG": {"name_de": "Aargau",          "name_en": "Aargau",         "financial_center": False},
    "TG": {"name_de": "Thurgau",         "name_en": "Thurgau",        "financial_center": False},
    "TI": {"name_de": "Tessin",          "name_en": "Ticino",         "financial_center": False},
    "VD": {"name_de": "Waadt",           "name_en": "Vaud",           "financial_center": False},
    "VS": {"name_de": "Wallis",          "name_en": "Valais",         "financial_center": False},
    "NE": {"name_de": "Neuenburg",       "name_en": "Neuchâtel",      "financial_center": False},
    "GE": {"name_de": "Genf",            "name_en": "Geneva",         "financial_center": True},
    "JU": {"name_de": "Jura",            "name_en": "Jura",           "financial_center": False},
}

GERMAN_STATES = {
    "BW": {"name": "Baden-Württemberg",      "capital": "Stuttgart"},
    "BY": {"name": "Bayern",                  "capital": "München"},
    "BE": {"name": "Berlin",                  "capital": "Berlin"},
    "BB": {"name": "Brandenburg",             "capital": "Potsdam"},
    "HB": {"name": "Bremen",                  "capital": "Bremen"},
    "HH": {"name": "Hamburg",                 "capital": "Hamburg"},
    "HE": {"name": "Hessen",                  "capital": "Wiesbaden"},
    "MV": {"name": "Mecklenburg-Vorpommern",  "capital": "Schwerin"},
    "NI": {"name": "Niedersachsen",           "capital": "Hannover"},
    "NW": {"name": "Nordrhein-Westfalen",     "capital": "Düsseldorf"},
    "RP": {"name": "Rheinland-Pfalz",         "capital": "Mainz"},
    "SL": {"name": "Saarland",                "capital": "Saarbrücken"},
    "SN": {"name": "Sachsen",                 "capital": "Dresden"},
    "ST": {"name": "Sachsen-Anhalt",          "capital": "Magdeburg"},
    "SH": {"name": "Schleswig-Holstein",      "capital": "Kiel"},
    "TH": {"name": "Thüringen",               "capital": "Erfurt"},
}
