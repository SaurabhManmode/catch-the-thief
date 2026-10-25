"""Record docs/demo.gif: the thief agent (left) and the jail dashboard (right).

    uvicorn demo.bank:app --port 8000 &
    python docs/record_demo.py
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

from playwright.sync_api import sync_playwright

URL = os.environ.get("BANK_URL", "http://localhost:8000")
OUT = os.path.join(os.path.dirname(__file__), "demo.gif")
SIZE = {"width": 720, "height": 800}
FONT = next(iter(glob.glob("/usr/share/fonts/opentype/inter/Inter-Bold.otf")), "")


def main():
    tmp = tempfile.mkdtemp()
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None, slow_mo=180)
        dash_ctx = b.new_context(viewport=SIZE, record_video_dir=f"{tmp}/dash", record_video_size=SIZE)
        thief_ctx = b.new_context(viewport=SIZE, record_video_dir=f"{tmp}/thief", record_video_size=SIZE)
        dash = dash_ctx.new_page()
        thief = thief_ctx.new_page()
        dash.goto(URL + "/jail/")
        thief.goto("about:blank")
        dash.wait_for_timeout(1200)

        thief.goto(URL + "/login")
        thief.type("#u", "alice", delay=70)
        thief.type("#p", "wonderland", delay=70)
        thief.click("#signin")
        thief.wait_for_url("**/account")
        thief.wait_for_timeout(900)
        thief.type("#to", "Totally Legit Ltd", delay=55)
        thief.type("#amount", "4900", delay=90)
        thief.click("#send")
        thief.wait_for_selector("#result")
        thief.wait_for_timeout(6000)

        dash_ctx.close()
        thief_ctx.close()
        b.close()

    left, right = glob.glob(f"{tmp}/thief/*.webm")[0], glob.glob(f"{tmp}/dash/*.webm")[0]
    label = ("drawtext=fontfile={f}:text='{t}':x=(w-text_w)/2:y=22:fontsize=26:fontcolor={c}")
    font = FONT or "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    graph = (
        f"[0:v]pad=iw:ih+70:0:70:color=0x14213d,{label.format(f=font, t='AI agent using Alice’s password', c='white')}[l];"
        f"[1:v]pad=iw:ih+70:0:70:color=0x0e1013,{label.format(f=font, t='The bank’s jail', c='0xff4d4f')}[r];"
        f"[l][r]hstack=inputs=2,fps=10,scale=1000:-1:flags=lanczos,split[a][b];"
        f"[a]palettegen=max_colors=96:stats_mode=diff[pal];[b][pal]paletteuse=dither=bayer:bayer_scale=4"
    )
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", left, "-i", right, "-filter_complex", graph,
                    "-shortest", OUT], check=True)
    shutil.rmtree(tmp)
    print(f"wrote {OUT} ({os.path.getsize(OUT) / 1e6:.1f} MB)")


if __name__ == "__main__":
    sys.exit(main())
