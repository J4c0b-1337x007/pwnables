# Professor — Writeup (תקציר)

באתגר **Professor** מנוצלת פונקציית `gets()` שנקראת מתוך ה-start routine. `gets()` אינה מבצעת בדיקת אורך הקלט ולכן ניתן לבצע **buffer overflow** ולדרוס את כתובת ה-RET. המתקפה מנצלת גם מנגנון **stack canary** על ידי דריסת ה-saved canary במחסנית וכן דריסת הערך הראשי ב-TLS canary, ובסופו של דבר מפעילה קוד שמשיג **shell** באמצעות ROP וכתיבה ל-GOT של `puts` כך ש-`puts` יצביע על `one_gadget`.

---

## גילוי ופירוט הפגיעות
- הפונקציה הפגיעה: `gets()` — קוראת קלט ללא הגבלת אורך → פתיחת אפשרות ל-stack buffer overflow.  
- המערכת כוללת מנגנון **stack canary** (השוואה עם ערך ב‑TLS). כדי לעקוף את ההגנה יש:
  1. לדרוס את ה‑saved canary השמור על ה‑stack.  
  2. לשנות גם את הערך שאליו מתבצעת ההשוואה (TLS canary / הערך הראשי), כדי שההשוואה תעבור למרות הדריסה.  
- לאחר דריסת ה‑RET נבנה **ROP chain** (return-oriented programming) — שינוי כתובת ה‑RET לכתובות gadget שמבצעות רצף פעולות עד ל‑`RET` הבא.

---

## שיטה וטכניקה (בנקודות)
1. **איתור gadgets**  
   - gadget = כתובת בזיכרון שמכילה רצף הוראות שימושיות (POP/MOV/ADD/RET) שניתן "לשרשר".  
   - דוגמה:
     ```python
     pop_rbx_rbp_r12_r13_r14_r15 = p64(0x000000000040138a)
     ```
     פירוק הדיסאсамбלי (דוגמה):
     ```
     0040138a 5b              POP        RBX
     0040138b 5d              POP        RBP
     0040138c 41 5c           POP        R12
     0040138e 41 5d           POP        R13
     00401390 41 5e           POP        R14
     00401392 41 5f           POP        R15
     00401394 c3              RET
     ```
   - כלים: **Ghidra**, **IDA** (IDA Free לעיתים מדויקת יותר).

2. **דילוג על ה-canary (canary bypass)**  
   - יש לשלב בדריסה גם שינוי בערך השמור וגם בערך ה‑TLS שההתאמה מולו מתבצעת, או למצוא דרך אחרת לעקוף את הבדיקה.  
   - ברגע שה-canary לא חוסם — ניתן לשרשר ROP.

3. **שינוי GOT של `puts` להצביע ל‑`one_gadget`**  
   - רעיון מרכזי: לשנות את כתובת ה‑GOT של `puts` כך שתצביע לכתובת `one_gadget` בתוך libc, ואז לקרוא ל־`puts` — מה שיריץ את ה‑one_gadget ויפתח shell.  
   - חישוב הפרש:  
     ```
     delta = offset_one_gadget - offset_puts
     ```
   - באמצעות gadget שמבצע כתיבה/חיבור בזיכרון מוסיפים את ה‑`delta` לערך שב‑GOT של `puts`. לאחר מכן קוראים ל‑`puts` (דרך ROP).

---

## כלים ושורות פקודה שימושיות
- ניתוח בינארי: **Ghidra**, **IDA Free**.  
- מציאת `one_gadget` ב‑libc:
  ```bash
  one_gadget ./libc.so.6
  ```
- מציאת offset של `puts` ב‑libc:
  ```bash
  objdump -T ./libc.so.6 | grep ' puts$'
  ```
- בדיקת PLT/דיסאסמבלי של `puts` בבינארי:
  ```bash
  objdump -d ./professor | grep "<puts@plt>"
  ```
- חיפוש gadgets:
  ```bash
  ROPgadget --binary professor --only "pop|ret|mov|add|xor"
  ```

---

## מבנה ה‑ROP (תקציר)
1. **Gadget ראשון**: הכנת רישומים (pop לערכים ל‑registers) כהכנה לכתיבה לזיכרון.  
2. **Gadget שני**: ביצוע הכתיבה/החיבור לכתובת ה‑GOT של `puts`.  
3. **קריאה ל‑puts**: בעזרת ה‑RET/הקריאה שתופעל, הזרימה תעבור לכתובת שהצבענו אליה (ה‑one_gadget) → SHELL.

---

## דגשים חשובים
- בדוק תמיד את מצב ההגנות: **ASLR, PIE, NX, RELRO** של הבינארי וה‑libc.  
- בשימוש ב‑RELRO מלא / GOT מוגן הגישה ל‑GOT עלולה להיכשל — יש להתאים גישות חלופיות (leak של libc + ret2libc וכו').  
- כתובות ה‑gadgets וה‑offsets תלויות בגרסת ה‑libc ובגרסת הבינארי — ודא התאמה מדויקת.

---

## סיכום
- ניצלנו את חוסר ההגבלה של `gets()` כדי לגרום ל‑buffer overflow.  
- עקפנו את מנגנון ה‑canary על‑ידי דריסת הערכים המתאימים (saved canary + TLS canary).  
- בעזרת ROP שינינו את כניסת ה‑GOT של `puts` כך שתצביע ל‑`one_gadget`, ובהרצת `puts` קיבלנו shell.

---

אם תרצה, אוכל להוסיף דוגמת קוד exploit (Python / pwntools) כקובץ נפרד — ציין אם זה מיועד לפרסום פומבי או לשימוש פרטני/לימודי בלבד.
