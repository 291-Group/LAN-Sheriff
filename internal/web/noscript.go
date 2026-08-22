package web

import (
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The page somebody sees when the dashboard cannot draw.
//
// # Why this is rendered in Go rather than written in index.html
//
// A <noscript> block written into index.html would be one fixed language, and
// English is the wrong guess for most of the world. Every other string in this
// product is translated twelve ways and switched from the toolbar, but the
// toolbar is drawn by the script that just did not run. So the one screen whose
// reader cannot possibly change the language is also the one screen that has to
// get the language right without being asked.
//
// The server already knows. Accept-Language is on the request, it costs nothing
// to read, and it is the only signal available before a single line of the
// dashboard executes. So the block is built here and injected into index.html on
// the way out.
//
// # Who is actually reading it
//
// Two people, and they want opposite things.
//
// One turned JavaScript off years ago on purpose, runs NoScript or uMatrix, and
// has a settled view that a page demanding scripts is a page extracting
// something. Telling that person to enable JavaScript is not an answer, it is
// the thing they already decided against. What they are owed is a straight
// account of what the scripts do, proof that nothing is loaded from anywhere
// else, and a way to get the data that does not involve giving in.
//
// The other has no idea JavaScript is off. Something in a corporate policy or
// an extension did it, and what they see is a monitoring tool that appears to
// be broken, which for a security product is worse than being broken. The first
// sentence is for them: the software is fine and still watching.
//
// # The commands are real
//
// Everything in the terminal section was run before it was written down. The
// point of the section is that a person who will not enable JavaScript is not
// thereby locked out of their own data, and that promise is worthless if the
// commands do not work. `lan-sheriff status` needs no password, no privilege
// and no running server, which makes it the one thing that always answers.

// noscriptText is the prose, per language. Kept as a struct rather than a map
// of keys so that a missing translation is a compile error rather than a blank
// paragraph on the one screen nobody tests.
type noscriptText struct {
	Title  string // heading
	Lede   string // the software is fine, nothing is broken
	WhyH   string
	Why    string
	SafeH  string
	Safe   string
	CLIH   string
	CLI    string
	C1     string // lan-sheriff status
	C2     string // export csv
	C3     string // export json
	C4     string // login, when a password is set
	Note   string
	Enable string // what happens if they do turn it on
}

// Twelve catalogues, the same twelve the dashboard carries. Canadian English in
// the en entry, and no em dashes anywhere.
var noscriptTexts = map[string]noscriptText{
	"en": {
		Title:  "This dashboard needs JavaScript",
		Lede:   "Your browser has JavaScript turned off, so the dashboard cannot draw. Nothing is wrong with LAN Sheriff. It is still running and still watching the network.",
		WhyH:   "Why it needs it",
		Why:    "The dashboard is a live view rather than a document: tables that re-sort as you filter them, a map that redraws, and connections appearing as they open. All of it is drawn in your browser from data this machine already holds, so there is no page-at-a-time version to fall back on.",
		SafeH:  "What it loads",
		Safe:   "Only files that came out of this binary. No content delivery network, no web fonts, no remote images, no analytics, and no third-party code of any kind. The server enforces that rather than promising it: every response carries default-src 'self', which makes a script from anywhere else inert even if one were somehow injected.",
		CLIH:   "If you would rather leave it off",
		CLI:    "You are not locked out of your own data. Most of what the dashboard shows can be read from a terminal instead.",
		C1:     "What this machine is sharing, and with whom. Needs no password, no privilege and no running server: it reads the database directly.",
		C2:     "Every destination seen, as a spreadsheet.",
		C3:     "The same data as JSON, for a script. Use view=flows for individual connections.",
		C4:     "If a password is set, sign in once and keep the cookie, then pass it to the calls above.",
		Note:   "Replace localhost with the address you use, and 2911 with your port if you changed it.",
		Enable: "Turning JavaScript on changes this browser only. LAN Sheriff itself behaves the same either way.",
	},
	"fr": {
		Title:  "Ce tableau de bord a besoin de JavaScript",
		Lede:   "JavaScript est désactivé dans votre navigateur, le tableau de bord ne peut donc pas s afficher. LAN Sheriff n a aucun problème : il fonctionne toujours et surveille toujours le réseau.",
		WhyH:   "Pourquoi il en a besoin",
		Why:    "Le tableau de bord est une vue vivante et non un document : des tableaux qui se retrient quand vous les filtrez, une carte qui se redessine, des connexions qui apparaissent à mesure qu elles s ouvrent. Tout cela est dessiné dans votre navigateur à partir de données que cette machine détient déjà ; il n existe donc pas de version page par page vers laquelle se replier.",
		SafeH:  "Ce qu il charge",
		Safe:   "Uniquement des fichiers issus de ce binaire. Aucun réseau de diffusion de contenu, aucune police distante, aucune image distante, aucune mesure d audience, aucun code tiers. Le serveur l impose au lieu de le promettre : chaque réponse porte default-src 'self', ce qui rend inerte tout script venu d ailleurs.",
		CLIH:   "Si vous préférez le laisser désactivé",
		CLI:    "Vos données ne vous sont pas fermées. L essentiel de ce que montre le tableau de bord se lit aussi depuis un terminal.",
		C1:     "Ce que cette machine partage, et avec qui. Sans mot de passe, sans privilège et sans serveur en cours : la commande lit directement la base.",
		C2:     "Toutes les destinations vues, sous forme de tableur.",
		C3:     "Les mêmes données en JSON, pour un script. Utilisez view=flows pour les connexions individuelles.",
		C4:     "Si un mot de passe est défini, connectez-vous une fois, gardez le témoin, puis passez-le aux appels ci-dessus.",
		Note:   "Remplacez localhost par l adresse que vous utilisez, et 2911 par votre port si vous l avez changé.",
		Enable: "Activer JavaScript ne change que ce navigateur. LAN Sheriff se comporte de la même façon dans les deux cas.",
	},
	"es": {
		Title:  "Este panel necesita JavaScript",
		Lede:   "Su navegador tiene JavaScript desactivado, así que el panel no puede dibujarse. LAN Sheriff no tiene ningún problema: sigue funcionando y sigue vigilando la red.",
		WhyH:   "Por qué lo necesita",
		Why:    "El panel es una vista viva, no un documento: tablas que se reordenan al filtrarlas, un mapa que se redibuja y conexiones que aparecen según se abren. Todo se dibuja en su navegador a partir de datos que esta máquina ya tiene, de modo que no hay una versión página a página a la que recurrir.",
		SafeH:  "Qué carga",
		Safe:   "Solo archivos salidos de este binario. Ninguna red de distribución de contenidos, ninguna fuente remota, ninguna imagen remota, ninguna analítica y ningún código de terceros. El servidor lo impone en lugar de prometerlo: cada respuesta lleva default-src 'self', lo que deja inerte cualquier script de otro origen.",
		CLIH:   "Si prefiere dejarlo desactivado",
		CLI:    "No se queda fuera de sus propios datos. Casi todo lo que muestra el panel puede leerse desde una terminal.",
		C1:     "Qué comparte esta máquina y con quién. No necesita contraseña, ni privilegios, ni un servidor en marcha: lee la base de datos directamente.",
		C2:     "Todos los destinos vistos, como hoja de cálculo.",
		C3:     "Los mismos datos en JSON, para un script. Use view=flows para conexiones individuales.",
		C4:     "Si hay contraseña, inicie sesión una vez y conserve la cookie; luego pásela a las llamadas anteriores.",
		Note:   "Sustituya localhost por la dirección que use, y 2911 por su puerto si lo cambió.",
		Enable: "Activar JavaScript solo cambia este navegador. LAN Sheriff se comporta igual en ambos casos.",
	},
	"de": {
		Title:  "Dieses Dashboard braucht JavaScript",
		Lede:   "In Ihrem Browser ist JavaScript abgeschaltet, deshalb kann das Dashboard nicht zeichnen. Mit LAN Sheriff ist nichts verkehrt: Es läuft weiter und überwacht das Netzwerk weiter.",
		WhyH:   "Warum es gebraucht wird",
		Why:    "Das Dashboard ist eine lebende Ansicht und kein Dokument: Tabellen, die sich beim Filtern neu sortieren, eine Karte, die sich neu zeichnet, und Verbindungen, die auftauchen, sobald sie geöffnet werden. All das wird in Ihrem Browser aus Daten gezeichnet, die dieser Rechner ohnehin hat; eine seitenweise Fassung zum Ausweichen gibt es deshalb nicht.",
		SafeH:  "Was geladen wird",
		Safe:   "Nur Dateien aus dieser Binärdatei. Kein Content Delivery Network, keine entfernten Schriften, keine entfernten Bilder, keine Analyse und kein Fremdcode. Der Server erzwingt das, statt es zu versprechen: Jede Antwort trägt default-src 'self', womit ein Skript von anderswo wirkungslos bleibt.",
		CLIH:   "Wenn Sie es lieber ausgeschaltet lassen",
		CLI:    "Sie sind nicht von Ihren eigenen Daten ausgesperrt. Das meiste, was das Dashboard zeigt, lässt sich auch im Terminal lesen.",
		C1:     "Was dieser Rechner teilt und mit wem. Ohne Passwort, ohne Rechte und ohne laufenden Server: Der Befehl liest die Datenbank direkt.",
		C2:     "Alle gesehenen Ziele als Tabelle.",
		C3:     "Dieselben Daten als JSON, für ein Skript. view=flows liefert einzelne Verbindungen.",
		C4:     "Wenn ein Passwort gesetzt ist, melden Sie sich einmal an, behalten das Cookie und geben es den Aufrufen oben mit.",
		Note:   "Ersetzen Sie localhost durch die Adresse, die Sie verwenden, und 2911 durch Ihren Port, falls Sie ihn geändert haben.",
		Enable: "JavaScript einzuschalten ändert nur diesen Browser. LAN Sheriff selbst verhält sich in beiden Fällen gleich.",
	},
	"pt": {
		Title:  "Este painel precisa de JavaScript",
		Lede:   "O seu navegador está com o JavaScript desligado, por isso o painel não consegue desenhar. Não há nada de errado com o LAN Sheriff: continua a funcionar e continua a vigiar a rede.",
		WhyH:   "Porque é necessário",
		Why:    "O painel é uma vista viva e não um documento: tabelas que se reordenam quando as filtra, um mapa que se redesenha e ligações que aparecem à medida que abrem. Tudo isso é desenhado no seu navegador a partir de dados que esta máquina já tem, pelo que não existe uma versão página a página para onde recuar.",
		SafeH:  "O que carrega",
		Safe:   "Apenas ficheiros saídos deste binário. Nenhuma rede de distribuição de conteúdos, nenhum tipo de letra remoto, nenhuma imagem remota, nenhuma analítica e nenhum código de terceiros. O servidor impõe isso em vez de prometer: cada resposta leva default-src 'self', o que torna inerte qualquer script vindo de outro sítio.",
		CLIH:   "Se preferir deixá-lo desligado",
		CLI:    "Não fica sem acesso aos seus próprios dados. Quase tudo o que o painel mostra também se lê num terminal.",
		C1:     "O que esta máquina partilha, e com quem. Sem palavra-passe, sem privilégios e sem servidor a correr: lê a base de dados directamente.",
		C2:     "Todos os destinos vistos, como folha de cálculo.",
		C3:     "Os mesmos dados em JSON, para um script. Use view=flows para ligações individuais.",
		C4:     "Se houver palavra-passe, autentique-se uma vez e guarde o cookie, depois passe-o às chamadas acima.",
		Note:   "Substitua localhost pelo endereço que usa, e 2911 pela sua porta se a tiver mudado.",
		Enable: "Ligar o JavaScript muda apenas este navegador. O LAN Sheriff comporta-se da mesma maneira em qualquer dos casos.",
	},
	"ru": {
		Title:  "Этой панели нужен JavaScript",
		Lede:   "В вашем браузере JavaScript отключён, поэтому панель не может отрисоваться. С LAN Sheriff всё в порядке: он работает и продолжает наблюдать за сетью.",
		WhyH:   "Зачем он нужен",
		Why:    "Панель является живым представлением, а не документом: таблицы пересортировываются при фильтрации, карта перерисовывается, соединения появляются по мере открытия. Всё это рисуется в браузере из данных, которые уже есть на этой машине, поэтому постраничной версии, к которой можно было бы отступить, просто нет.",
		SafeH:  "Что загружается",
		Safe:   "Только файлы из этого исполняемого файла. Никакой сети доставки контента, никаких внешних шрифтов, никаких внешних изображений, никакой аналитики и никакого стороннего кода. Сервер это не обещает, а обеспечивает: каждый ответ несёт default-src 'self', из-за чего сторонний скрипт остаётся бездействующим.",
		CLIH:   "Если предпочитаете не включать",
		CLI:    "Доступ к собственным данным у вас остаётся. Почти всё, что показывает панель, можно прочитать из терминала.",
		C1:     "Чем эта машина делится и с кем. Не нужны ни пароль, ни привилегии, ни запущенный сервер: команда читает базу напрямую.",
		C2:     "Все увиденные назначения в виде таблицы.",
		C3:     "Те же данные в JSON, для скрипта. Для отдельных соединений используйте view=flows.",
		C4:     "Если задан пароль, войдите один раз, сохраните cookie и передавайте его вызовам выше.",
		Note:   "Замените localhost на используемый вами адрес, а 2911 на свой порт, если вы его меняли.",
		Enable: "Включение JavaScript меняет только этот браузер. Сам LAN Sheriff работает одинаково в обоих случаях.",
	},
	"zh": {
		Title:  "此仪表板需要 JavaScript",
		Lede:   "您的浏览器已关闭 JavaScript，因此仪表板无法绘制。LAN Sheriff 本身没有任何问题：它仍在运行，也仍在监视网络。",
		WhyH:   "为什么需要它",
		Why:    "仪表板是实时视图而不是文档：表格会随筛选重新排序，地图会重绘，连接会在建立时逐条出现。这一切都是在您的浏览器中，用本机已有的数据绘制的，因此没有可退回的分页版本。",
		SafeH:  "它加载什么",
		Safe:   "只有从这个可执行文件里取出的文件。没有内容分发网络，没有远程字体，没有远程图片，没有统计分析，也没有任何第三方代码。服务器不是承诺而是强制：每个响应都带有 default-src 'self'，即使有脚本被注入也无法运行。",
		CLIH:   "如果您宁愿不开启",
		CLI:    "您并未被挡在自己的数据之外。仪表板显示的大部分内容都可以在终端里读到。",
		C1:     "本机在共享什么，与谁共享。不需要密码、不需要权限、也不需要正在运行的服务器：它直接读取数据库。",
		C2:     "所有见过的目的地，以电子表格形式。",
		C3:     "同样的数据，以 JSON 形式供脚本使用。单条连接请用 view=flows。",
		C4:     "若已设置密码，先登录一次并保存 cookie，然后把它带给上面的调用。",
		Note:   "把 localhost 换成您使用的地址；若改过端口，也把 2911 换成您的端口。",
		Enable: "开启 JavaScript 只影响这个浏览器。LAN Sheriff 本身两种情况下行为相同。",
	},
	"ja": {
		Title:  "このダッシュボードには JavaScript が必要です",
		Lede:   "ブラウザーで JavaScript が無効になっているため、ダッシュボードを描画できません。LAN Sheriff に異常はありません。動作を続け、ネットワークを見張っています。",
		WhyH:   "なぜ必要か",
		Why:    "ダッシュボードは文書ではなく生きた表示です。絞り込むたびに並び替わる表、描き直される地図、開いた端から現れる接続。いずれもこの端末がすでに持つデータからブラウザー側で描いており、ページ単位で代替する版はありません。",
		SafeH:  "何を読み込むか",
		Safe:   "この実行ファイルから出たファイルだけです。コンテンツ配信網も、外部のフォントも、外部の画像も、解析も、第三者のコードも一切ありません。サーバーは約束ではなく強制しています。すべての応答が default-src 'self' を伴い、外部から来た script は動きません。",
		CLIH:   "有効にしたくない場合",
		CLI:    "ご自身のデータから締め出されるわけではありません。ダッシュボードが示す内容の大半は端末からも読めます。",
		C1:     "この端末が何を誰と共有しているか。パスワードも権限も、動作中のサーバーも不要です。データベースを直接読みます。",
		C2:     "見えたすべての宛先を表計算形式で。",
		C3:     "同じ内容を JSON で、スクリプト向けに。個々の接続は view=flows を使います。",
		C4:     "パスワードを設定している場合は一度ログインして cookie を保存し、上の呼び出しに渡します。",
		Note:   "localhost はお使いのアドレスに、ポートを変更している場合は 2911 もご自身のポートに置き換えてください。",
		Enable: "JavaScript を有効にしても変わるのはこのブラウザーだけです。LAN Sheriff 自体の動きはどちらでも同じです。",
	},
	"hi": {
		Title:  "इस डैशबोर्ड को JavaScript चाहिए",
		Lede:   "आपके ब्राउज़र में JavaScript बंद है, इसलिए डैशबोर्ड बन नहीं पा रहा। LAN Sheriff में कोई गड़बड़ी नहीं है: वह चल रहा है और नेटवर्क पर नज़र रखे हुए है।",
		WhyH:   "इसकी ज़रूरत क्यों है",
		Why:    "डैशबोर्ड कोई दस्तावेज़ नहीं, एक जीवित दृश्य है: छाँटने पर फिर से क्रम बदलती तालिकाएँ, दोबारा बनता नक्शा, और खुलते ही दिखते कनेक्शन। यह सब आपके ब्राउज़र में उसी डेटा से बनता है जो इस मशीन के पास पहले से है, इसलिए पन्ना-दर-पन्ना कोई विकल्प मौजूद ही नहीं है।",
		SafeH:  "यह क्या लोड करता है",
		Safe:   "केवल वही फ़ाइलें जो इसी बाइनरी से निकली हैं। कोई कंटेंट डिलीवरी नेटवर्क नहीं, कोई बाहरी फ़ॉन्ट नहीं, कोई बाहरी छवि नहीं, कोई एनालिटिक्स नहीं, और किसी तीसरे पक्ष का कोई कोड नहीं। सर्वर इसका वादा नहीं करता, इसे लागू करता है: हर उत्तर में default-src 'self' रहता है, जिससे कहीं और से आया script निष्क्रिय रहता है।",
		CLIH:   "यदि आप इसे बंद ही रखना चाहें",
		CLI:    "आप अपने ही डेटा से बाहर नहीं हैं। डैशबोर्ड जो दिखाता है उसका अधिकांश टर्मिनल से भी पढ़ा जा सकता है।",
		C1:     "यह मशीन क्या साझा कर रही है, और किसके साथ। न पासवर्ड चाहिए, न विशेषाधिकार, न चलता हुआ सर्वर: यह डेटाबेस सीधे पढ़ता है।",
		C2:     "देखे गए सभी गंतव्य, स्प्रेडशीट के रूप में।",
		C3:     "वही डेटा JSON में, किसी स्क्रिप्ट के लिए। अलग-अलग कनेक्शन के लिए view=flows लें।",
		C4:     "यदि पासवर्ड लगा है तो एक बार साइन इन करके cookie रखें, फिर ऊपर के कॉल में वही दें।",
		Note:   "localhost की जगह अपना पता रखें, और यदि पोर्ट बदला है तो 2911 की जगह अपना पोर्ट।",
		Enable: "JavaScript चालू करने से केवल यही ब्राउज़र बदलता है। LAN Sheriff का व्यवहार दोनों हालात में एक जैसा रहता है।",
	},
	"bn": {
		Title:  "এই ড্যাশবোর্ডের জন্য JavaScript দরকার",
		Lede:   "আপনার ব্রাউজারে JavaScript বন্ধ, তাই ড্যাশবোর্ড আঁকা যাচ্ছে না। LAN Sheriff-এর কিছুই হয়নি: এটি চলছে এবং নেটওয়ার্কের উপর নজর রাখছে।",
		WhyH:   "কেন দরকার",
		Why:    "ড্যাশবোর্ড কোনও নথি নয়, একটি জীবন্ত দৃশ্য: ছাঁকলেই নতুন করে সাজানো তালিকা, নতুন করে আঁকা মানচিত্র, আর খোলার সঙ্গে সঙ্গে দেখা দেওয়া সংযোগ। সবটাই আপনার ব্রাউজারে আঁকা হয় এই যন্ত্রে থাকা তথ্য থেকে, তাই পাতা-ধরে-পাতা কোনও বিকল্প সংস্করণ নেই।",
		SafeH:  "এটি কী নেয়",
		Safe:   "কেবল এই বাইনারি থেকে বেরোনো ফাইল। কোনও কনটেন্ট ডেলিভারি নেটওয়ার্ক নয়, কোনও দূরের ফন্ট নয়, কোনও দূরের ছবি নয়, কোনও অ্যানালিটিক্স নয়, তৃতীয় পক্ষের কোনও কোডও নয়। সার্ভার এটি প্রতিশ্রুতি দেয় না, বাধ্য করে: প্রতিটি উত্তরে default-src 'self' থাকে, ফলে বাইরের কোনও script কাজ করে না।",
		CLIH:   "যদি বন্ধই রাখতে চান",
		CLI:    "নিজের তথ্য থেকে আপনি বঞ্চিত নন। ড্যাশবোর্ড যা দেখায় তার বেশিরভাগই টার্মিনাল থেকেও পড়া যায়।",
		C1:     "এই যন্ত্র কী ভাগ করছে, আর কার সঙ্গে। পাসওয়ার্ড লাগে না, বিশেষ অনুমতি লাগে না, চালু সার্ভারও লাগে না: এটি ডেটাবেস সরাসরি পড়ে।",
		C2:     "দেখা সব গন্তব্য, স্প্রেডশিট আকারে।",
		C3:     "একই তথ্য JSON-এ, স্ক্রিপ্টের জন্য। আলাদা সংযোগের জন্য view=flows।",
		C4:     "পাসওয়ার্ড দেওয়া থাকলে একবার সাইন ইন করে cookie রাখুন, তারপর উপরের ডাকে সেটি দিন।",
		Note:   "localhost-এর জায়গায় আপনার ঠিকানা বসান, আর পোর্ট বদলে থাকলে 2911-এর জায়গায় আপনার পোর্ট।",
		Enable: "JavaScript চালু করলে কেবল এই ব্রাউজারই বদলায়। LAN Sheriff নিজে দুই ক্ষেত্রেই একইভাবে চলে।",
	},
	"ar": {
		Title:  "هذه اللوحة تحتاج إلى JavaScript",
		Lede:   "\u200fJavaScript معطَّل في متصفحك، لذا تعذّر رسم اللوحة. لا خلل في LAN Sheriff: فهو ما زال يعمل وما زال يراقب الشبكة.",
		WhyH:   "لماذا يحتاج إليه",
		Why:    "اللوحة عرض حيّ لا مستند: جداول تُعاد ترتيبها مع كل تصفية، وخريطة تُعاد رسمها، واتصالات تظهر لحظة فتحها. كل ذلك يُرسم في متصفحك من بيانات يملكها هذا الجهاز أصلاً، ولذلك لا توجد نسخة صفحة بصفحة يمكن الرجوع إليها.",
		SafeH:  "ما الذي يُحمَّل",
		Safe:   "ملفات خرجت من هذا الملف التنفيذي فقط. لا شبكة توصيل محتوى، ولا خطوط بعيدة، ولا صور بعيدة، ولا تحليلات، ولا أي شيفرة من طرف ثالث. والخادم يفرض ذلك بدل أن يَعِد به: كل استجابة تحمل \u2066default-src 'self'\u2069، مما يُبطل أي script قادم من مكان آخر.",
		CLIH:   "إن فضّلت إبقاءه معطَّلاً",
		CLI:    "أنت لست محروماً من بياناتك. معظم ما تعرضه اللوحة يمكن قراءته من الطرفية أيضاً.",
		C1:     "ماذا يشارك هذا الجهاز، ومع من. لا يحتاج كلمة مرور ولا صلاحية ولا خادماً قيد التشغيل: فهو يقرأ قاعدة البيانات مباشرة.",
		C2:     "كل الوجهات التي رُصدت، بصيغة جدول بيانات.",
		C3:     "البيانات نفسها بصيغة JSON لأجل برنامج نصي. وللاتصالات المفردة استخدم view=flows.",
		C4:     "إن كانت هناك كلمة مرور، سجّل الدخول مرة واحدة واحتفظ بملف تعريف الارتباط، ثم مرّره للطلبات أعلاه.",
		Note:   "استبدل localhost بالعنوان الذي تستخدمه، و2911 بمنفذك إن كنت قد غيّرته.",
		Enable: "تفعيل JavaScript يغيّر هذا المتصفح وحده. أما LAN Sheriff نفسه فسلوكه واحد في الحالتين.",
	},
	"he": {
		Title:  "לוח הבקרה הזה זקוק ל‑JavaScript",
		Lede:   "\u200fJavaScript כבוי בדפדפן שלך, ולכן לוח הבקרה אינו יכול להיווצר. שום דבר לא תקול ב‑LAN Sheriff: הוא פועל וממשיך לפקח על הרשת.",
		WhyH:   "למה הוא נחוץ",
		Why:    "לוח הבקרה הוא תצוגה חיה ולא מסמך: טבלאות שמסתדרות מחדש עם כל סינון, מפה שמצטיירת מחדש, וחיבורים שמופיעים ברגע שהם נפתחים. הכול מצויר בדפדפן שלך מתוך נתונים שכבר נמצאים במחשב הזה, ולכן אין גרסה עמוד‑אחר‑עמוד לחזור אליה.",
		SafeH:  "מה נטען",
		Safe:   "רק קבצים שיצאו מקובץ ההרצה הזה. בלי רשת אספקת תוכן, בלי גופנים מרוחקים, בלי תמונות מרוחקות, בלי אנליטיקה ובלי שום קוד צד שלישי. השרת אוכף זאת במקום להבטיח: כל תשובה נושאת \u2066default-src 'self'\u2069, וכך script שהגיע ממקום אחר נשאר חסר פעולה.",
		CLIH:   "אם עדיף לך להשאיר אותו כבוי",
		CLI:    "אינך נעול מחוץ לנתונים של עצמך. את רוב מה שלוח הבקרה מציג אפשר לקרוא גם מהמסוף.",
		C1:     "מה המחשב הזה משתף, ועם מי. בלי סיסמה, בלי הרשאות ובלי שרת פעיל: הפקודה קוראת ישירות ממסד הנתונים.",
		C2:     "כל היעדים שנצפו, כגיליון אלקטרוני.",
		C3:     "אותם נתונים כ‑JSON, עבור סקריפט. לחיבורים בודדים השתמשו ב‑view=flows.",
		C4:     "אם מוגדרת סיסמה, היכנסו פעם אחת ושמרו את העוגייה, ואז העבירו אותה לקריאות שלמעלה.",
		Note:   "החליפו את localhost בכתובת שאתם משתמשים בה, ואת 2911 ביציאה שלכם אם שיניתם אותה.",
		Enable: "הפעלת JavaScript משנה את הדפדפן הזה בלבד. LAN Sheriff עצמו מתנהג אותו הדבר כך או כך.",
	},
}

// rtl is the pair that mirrors, matching the dashboard.
var rtl = map[string]bool{"ar": true, "he": true}

// pickLang chooses a catalogue from Accept-Language.
//
// Deliberately tolerant. The header is frequently malformed by proxies and
// embedded browsers, and the cost of getting it wrong is a page in the wrong
// language rather than an error, so anything unparseable simply scores zero and
// English wins by default.
func pickLang(header string) string {
	type pref struct {
		tag string
		q   float64
		ord int
	}
	var prefs []pref
	for i, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, q := part, 1.0
		if semi := strings.Index(part, ";"); semi >= 0 {
			tag = strings.TrimSpace(part[:semi])
			if v := strings.TrimSpace(part[semi+1:]); strings.HasPrefix(v, "q=") {
				if f, err := strconv.ParseFloat(v[2:], 64); err == nil {
					q = f
				}
			}
		}
		// zh-Hans, pt-BR and en-CA all collapse to their base, which is the
		// granularity the catalogues have.
		if dash := strings.Index(tag, "-"); dash >= 0 {
			tag = tag[:dash]
		}
		tag = strings.ToLower(tag)
		if q > 0 {
			prefs = append(prefs, pref{tag, q, i})
		}
	}
	// Stable: equal q keeps header order, which is what the header means.
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })
	for _, p := range prefs {
		if _, ok := noscriptTexts[p.tag]; ok {
			return p.tag
		}
	}
	return "en"
}

// The commands. Not translated, because they are typed rather than read, and a
// translated command is a command that does not run.
const (
	cmdStatus = "lan-sheriff status"
	cmdCSV    = "curl -s 'http://localhost:2911/api/export?view=egress&format=csv' -o destinations.csv"
	cmdJSON   = "curl -s 'http://localhost:2911/api/export?view=flows&format=json'"
	cmdLogin  = "curl -s -c jar -X POST http://localhost:2911/api/auth/login \\\n     -H 'Content-Type: application/json' -d '{\"password\":\"YOURS\"}'\ncurl -s -b jar 'http://localhost:2911/api/summary'"
)

// The stylesheet is inlined rather than reusing the dashboard's, which is a
// fingerprinted asset the build renames on every change. 'unsafe-inline' is
// already allowed for style-src, so this needs no policy change. Both themes are
// answered from prefers-color-scheme, because the script that reads the saved
// theme is exactly the script that did not run.
const noscriptCSS = `
.ns{position:fixed;inset:0;overflow:auto;padding:2.5rem 1.25rem;
 font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
 background:#f4f6fb;color:#1c2430}
.ns-w{max-width:46rem;margin:0 auto}
.ns-badge{font-size:.8125rem;letter-spacing:.08em;text-transform:uppercase;
 opacity:.62;margin:0 0 .75rem}
.ns h1{font-size:1.6rem;line-height:1.25;margin:0 0 .6rem;font-weight:600}
.ns h2{font-size:1rem;margin:1.9rem 0 .45rem;font-weight:600}
.ns p{margin:0 0 .85rem}
.ns .ns-lede{font-size:1.075rem;opacity:.9}
.ns-card{background:rgba(255,255,255,.72);border:1px solid rgba(18,24,36,.1);
 border-radius:16px;padding:1.75rem 1.9rem;
 box-shadow:0 1px 2px rgba(18,24,36,.05),0 12px 32px rgba(18,24,36,.07);
 -webkit-backdrop-filter:saturate(180%) blur(20px);
 backdrop-filter:saturate(180%) blur(20px)}
.ns-cmd{margin:1rem 0 1.35rem}
.ns-cmd p{font-size:.9375rem;opacity:.78;margin:0 0 .4rem}
.ns pre{margin:0;padding:.7rem .85rem;border-radius:10px;
 background:rgba(18,24,36,.055);border:1px solid rgba(18,24,36,.08);
 font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 color:#12202e;
 /* Wrapped rather than scrolled. A command behind a horizontal scrollbar is a
    command somebody copies half of, and these are the whole point of the page.
    Soft wrapping does not alter what a selection yields. */
 white-space:pre-wrap;overflow-wrap:anywhere}
.ns-note{font-size:.875rem;opacity:.68;margin-top:1.6rem;
 border-top:1px solid rgba(18,24,36,.1);padding-top:1rem}
[dir=rtl] .ns pre{direction:ltr;text-align:left}
@media (prefers-color-scheme:dark){
 .ns{background:#12151c;color:#e4e9f2}
 .ns-card{background:rgba(30,36,48,.66);border-color:rgba(255,255,255,.09);
  box-shadow:0 1px 2px rgba(0,0,0,.3),0 12px 32px rgba(0,0,0,.34)}
 .ns pre{background:rgba(0,0,0,.32);border-color:rgba(255,255,255,.09);
  color:#d8e2ef}
 .ns-note{border-top-color:rgba(255,255,255,.1)}
}
@media (max-width:34rem){
 .ns{padding:1.25rem .75rem}
 .ns-card{padding:1.25rem 1.1rem;border-radius:13px}
 .ns h1{font-size:1.4rem}
}
`

// renderNoscript builds the block for one language.
func renderNoscript(lang string) string {
	t, ok := noscriptTexts[lang]
	if !ok {
		t, lang = noscriptTexts["en"], "en"
	}
	e := html.EscapeString

	cmd := func(caption, command string) string {
		return `<div class="ns-cmd"><p>` + e(caption) + `</p><pre>` + e(command) + `</pre></div>`
	}

	var b strings.Builder
	b.WriteString("<noscript><style>" + noscriptCSS + "</style>")
	b.WriteString(`<div class="ns"><div class="ns-w"><div class="ns-card">`)
	b.WriteString(`<p class="ns-badge">LAN Sheriff</p>`)
	b.WriteString(`<h1>` + e(t.Title) + `</h1>`)
	b.WriteString(`<p class="ns-lede">` + e(t.Lede) + `</p>`)
	b.WriteString(`<h2>` + e(t.WhyH) + `</h2><p>` + e(t.Why) + `</p>`)
	b.WriteString(`<h2>` + e(t.SafeH) + `</h2><p>` + e(t.Safe) + `</p>`)
	b.WriteString(`<h2>` + e(t.CLIH) + `</h2><p>` + e(t.CLI) + `</p>`)
	b.WriteString(cmd(t.C1, cmdStatus))
	b.WriteString(cmd(t.C2, cmdCSV))
	b.WriteString(cmd(t.C3, cmdJSON))
	b.WriteString(cmd(t.C4, cmdLogin))
	b.WriteString(`<p class="ns-note">` + e(t.Note) + ` ` + e(t.Enable) + `</p>`)
	b.WriteString(`</div></div></div></noscript>`)
	return b.String()
}

// The two tags rewritten on the way out. Matched by pattern rather than by
// literal because the bundler is free to reformat attributes, and a literal
// that stops matching would remove the whole page silently, which is the exact
// failure this product keeps having to relearn. injectNoscript reports whether
// it worked so the caller can assert instead of hope.
var (
	htmlTagRe = regexp.MustCompile(`(?i)<html[^>]*>`)
	bodyTagRe = regexp.MustCompile(`(?i)<body[^>]*>`)
)

// injectNoscript sets the document language and direction and inserts the
// block. It returns false if the document was not what was expected, which the
// caller treats as a reason to serve the original untouched: a dashboard with
// no fallback page is a great deal better than no dashboard.
func injectNoscript(doc []byte, lang string) ([]byte, bool) {
	loc := bodyTagRe.FindIndex(doc)
	if loc == nil {
		return doc, false
	}
	dir := "ltr"
	if rtl[lang] {
		dir = "rtl"
	}
	out := htmlTagRe.ReplaceAll(doc, []byte(`<html lang="`+lang+`" dir="`+dir+`">`))
	// Re-find: the html tag replacement shifts every offset after it.
	loc = bodyTagRe.FindIndex(out)
	if loc == nil {
		return doc, false
	}
	block := []byte(renderNoscript(lang))
	res := make([]byte, 0, len(out)+len(block))
	res = append(res, out[:loc[1]]...)
	res = append(res, block...)
	res = append(res, out[loc[1]:]...)
	return res, true
}
