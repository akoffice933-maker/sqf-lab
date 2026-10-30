import json

from sqflab.cli import main


def test_addr_command(capsys):
    assert main(["addr", "--priv", "1"]) == 0
    out = capsys.readouterr().out
    assert "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" in out


def test_p2g_commands(capsys):
    assert main(["p2g", "clue2"]) == 0
    assert "directionsshouldbespelledandcheckthefirst" in capsys.readouterr().out
    assert main(["p2g", "ledger"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_pairs_tested"] == 37_373_278_038


def test_battleship_cell(capsys):
    assert main(["battleship", "cell", "--bits", "32", "--col", "3", "--row", "4"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cell"] == "D5" and payload["width"] > 0


def test_solve_command(capsys):
    from sqflab.curve import compress, scalar_mult

    k = (1 << 17) + 1234
    pub = compress(scalar_mult(k)).hex()
    assert main(["solve", "--pub", pub, "--bits", "18"]) == 0
    assert "verified     : True" in capsys.readouterr().out
