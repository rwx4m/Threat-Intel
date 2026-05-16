/*
    YARA Rule — Phishing Network: a-gratis.uk
    ==========================================
    Author      : rwx4m
    Date        : 2026-05-16
    Version     : 1.0
    TLP         : WHITE
    Reference   : https://sudo-rwx4m.my.id/
    Description : Detects phishing pages belonging to the a-gratis.uk
                  network targeting government social benefit programs
                  in Indonesia and Malaysia. All strings verified against
                  live source HTML captured on 2026-05-16.

    Verified sources:
      - https://bansos-terkini.a-gratis.uk/        (HTTP 200, 17327 bytes)
      - https://bantuan-ppr-terkini.a-gratis.uk/   (HTTP 200, 30476 bytes)
      - https://daftar-segera.a-gratis.uk/          (HTTP 200, 20239 bytes)
      - https://daftar-segeraa.a-gratis.uk/         (HTTP 200)
      - https://jawatan-kosong-terkini.a-gratis.uk/ (HTTP 200, 28870 bytes)
*/

rule Phishing_aGratisUK_Domain
{
    meta:
        description = "Detects any page hosted under the a-gratis.uk phishing domain"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "HIGH"
        reference   = "https://sudo-rwx4m.my.id/"

    strings:
        $domain = "a-gratis.uk" ascii wide nocase

    condition:
        $domain
}


rule Phishing_aGratisUK_Indonesia_PKH
{
    meta:
        description = "Detects phishing page impersonating PKH Kemensos Indonesia — bansos-terkini.a-gratis.uk"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "HIGH"
        source      = "bansos-terkini.a-gratis.uk (source HTML, 2026-05-16)"

    strings:
        /* Confirmed in bansos-terkini source HTML */
        $lure_program   = "Bantuan PKH"        ascii wide
        $lure_amount    = "1.500.000"           ascii wide
        $form_field     = "Nomor Telegram"      ascii wide
        $nextjs         = "_next/static"        ascii wide
        $domain         = "a-gratis.uk"         ascii wide nocase
        $logo_alt       = "Logo Kemensos"       ascii wide

    condition:
        $domain and $nextjs and
        2 of ($lure_program, $lure_amount, $form_field, $logo_alt)
}


rule Phishing_aGratisUK_Malaysia_PPR
{
    meta:
        description = "Detects phishing page impersonating PPR housing program Malaysia — bantuan-ppr-terkini.a-gratis.uk"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "HIGH"
        source      = "bantuan-ppr-terkini.a-gratis.uk (source HTML, 2026-05-16)"

    strings:
        /* Confirmed in bantuan-ppr-terkini source HTML */
        $lure_program   = "PROGRAM PERUMAHAN RAKYAT"  ascii wide
        $form_field     = "Nombor Telegram"            ascii wide
        $fake_feed      = "Berjaya mendaftar"          ascii wide
        $nextjs         = "_next/static"               ascii wide
        $domain         = "a-gratis.uk"                ascii wide nocase

    condition:
        $domain and $nextjs and
        2 of ($lure_program, $form_field, $fake_feed)
}


rule Phishing_aGratisUK_Malaysia_JobScam
{
    meta:
        description = "Detects phishing page impersonating Malaysian government job portal — jawatan-kosong-terkini.a-gratis.uk"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "HIGH"
        source      = "jawatan-kosong-terkini.a-gratis.uk (source HTML, 2026-05-16)"

    strings:
        /* Confirmed in jawatan-kosong-terkini source HTML */
        $lure_title     = "Jawatan Kosong"    ascii wide
        $lure_salary_1  = "RM 1"              ascii wide
        $lure_salary_2  = "RM 2"              ascii wide
        $lure_salary_3  = "RM 3"              ascii wide
        $nextjs         = "_next/static"      ascii wide
        $domain         = "a-gratis.uk"       ascii wide nocase

    condition:
        $domain and $nextjs and
        $lure_title and
        any of ($lure_salary_1, $lure_salary_2, $lure_salary_3)
}


rule Phishing_aGratisUK_Indonesia_Generic
{
    meta:
        description = "Detects generic registration phishing page targeting Indonesia — daftar-segera.a-gratis.uk"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "HIGH"
        source      = "daftar-segera.a-gratis.uk (source HTML, 2026-05-16)"

    strings:
        /* Confirmed in daftar-segera source HTML */
        $lure_title     = "Daftar Sekarang"   ascii wide
        $form_field     = "Nomor Telegram"    ascii wide
        $nextjs         = "_next/static"      ascii wide
        $domain         = "a-gratis.uk"       ascii wide nocase

    condition:
        $domain and $nextjs and
        $lure_title and $form_field
}


rule Phishing_aGratisUK_Network_Broad
{
    meta:
        description = "Broad detection for any a-gratis.uk phishing kit variant — catches all known subdomains"
        author      = "rwx4m"
        date        = "2026-05-16"
        tlp         = "WHITE"
        confidence  = "MEDIUM"
        note        = "Broader rule — may produce false positives if a-gratis.uk domain is reused legitimately"

    strings:
        $domain         = "a-gratis.uk"            ascii wide nocase
        $nextjs         = "_next/static"            ascii wide
        $tele_id        = "Nomor Telegram"          ascii wide
        $tele_my        = "Nombor Telegram"         ascii wide
        $feed_my        = "Berjaya mendaftar"       ascii wide
        $ppr            = "PROGRAM PERUMAHAN RAKYAT" ascii wide
        $pkh            = "Bantuan PKH"             ascii wide
        $jk             = "Jawatan Kosong"          ascii wide
        $daftar         = "Daftar Sekarang"         ascii wide

    condition:
        $domain and $nextjs and
        any of ($tele_id, $tele_my, $feed_my, $ppr, $pkh, $jk, $daftar)
}
