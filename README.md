# Cobra

سكربتات مفتوحة مصدر لي اختبار الاختراق الأخلاقي 
 تشغيل الأداة

بعد فك الضغط عن Thecobra.zip، ادخل إلى المجلد وشغل الأداة:

unzip cobra.zip
cd cobra
python3 cobra.py


عند التشغيل، سيطلب منك إدخال نطاق أو عنوان IP، مثال:

Enter target domain/IP: example.com




3️⃣ الميزات التي تقوم بها الأداة

✅ جمع المعلومات (WHOIS)
✅ استخراج النطاقات الفرعية (Subfinder)
✅ فحص المنافذ والخدمات (Nmap)
✅ تحليل الثغرات (Nikto)
✅ جمع الإيميلات والمعلومات (TheHarvester)



4️⃣ استخراج التقرير

بعد انتهاء الفحص، سيتم حفظ النتائج في ملف JSON بنفس اسم الهدف، مثل:

cat example.com_report.json




🎯 مثال عملي

إذا كنت تريد فحص نطاق مثل example.com، شغل:

python3 cobra.py


ثم أدخل:

Enter target domain/IP: example.com


وستحصل على تقرير مفصل حول الهدف.
