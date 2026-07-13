"""안심톡 대표 이미지(600x600) 생성 — 방패(보호) + 체크 + 말풍선 + '안심톡'."""
from PIL import Image, ImageDraw, ImageFont

S = 600
img = Image.new("RGB", (S, S), "#12233A")
d = ImageDraw.Draw(img)

# 배경 세로 그라데이션 (신뢰감 있는 딥네이비 → 틸)
top = (18, 35, 58)      # #12233A
bot = (23, 82, 92)      # #17525C
for y in range(S):
    t = y / S
    r = int(top[0] + (bot[0]-top[0])*t)
    g = int(top[1] + (bot[1]-top[1])*t)
    b = int(top[2] + (bot[2]-top[2])*t)
    d.line([(0, y), (S, y)], fill=(r, g, b))

# 방패 도형 (중앙 상단)
cx = S // 2
shield_top = 120
shield_w = 230
shield_h = 250
left = cx - shield_w // 2
right = cx + shield_w // 2
# 방패 윤곽: 위는 평평, 아래는 뾰족
pts = [
    (left, shield_top + 30),
    (cx, shield_top),
    (right, shield_top + 30),
    (right, shield_top + shield_h * 0.55),
    (cx, shield_top + shield_h),
    (left, shield_top + shield_h * 0.55),
]
# 방패 채움 (따뜻한 옐로우 = 카카오 톤, 안심)
d.polygon(pts, fill="#FFD43B")

# 방패 안 말풍선 (대화 = 톡)
bx0, by0, bx1, by1 = cx-70, shield_top+70, cx+70, shield_top+150
d.rounded_rectangle([bx0, by0, bx1, by1], radius=24, fill="#12233A")
# 말풍선 꼬리
d.polygon([(cx-18, by1-4), (cx+12, by1-4), (cx-8, by1+26)], fill="#12233A")
# 말풍선 안 체크(안전 확인)
d.line([(cx-34, (by0+by1)//2), (cx-8, (by0+by1)//2+22), (cx+40, (by0+by1)//2-24)],
       fill="#FFD43B", width=14, joint="curve")

# 텍스트 '안심톡'
def load_font(size):
    for p in ["/System/Library/Fonts/AppleSDGothicNeo.ttc",
              "/System/Library/Fonts/Supplemental/AppleGothic.ttf"]:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()

font = load_font(96)
text = "안심톡"
tb = d.textbbox((0, 0), text, font=font)
tw, th = tb[2]-tb[0], tb[3]-tb[1]
d.text(((S-tw)//2 - tb[0], 430 - tb[1]), text, font=font, fill="#FFFFFF")

# 서브 태그라인
sfont = load_font(30)
sub = "문자 사기 판별"
sb = d.textbbox((0, 0), sub, font=sfont)
sw = sb[2]-sb[0]
d.text(((S-sw)//2 - sb[0], 548 - sb[1]), sub, font=sfont, fill="#8FB3C9")

img.save("/Users/billybaek/Desktop/ansimtalk/logo.png", "PNG")
print("saved /Users/billybaek/Desktop/ansimtalk/logo.png", img.size)
