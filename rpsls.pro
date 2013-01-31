%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Fakultet organizacije i informatike Varaždin                                   
% Sveučilište u Zagrebu 
%
% Seminarski rad iz kolegija Logičko programiranje  
%   -> Igra: Rock-Paper-Scissors-Lizard-Spock 
%			 (Kamen-Papir-Škare-Gušter-Spock)
% 
% Josip Žemberi, 
% Diplomski studij: Informacijsko i programsko inženjerstvo   
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Import potrebnih predikata iz odgovarajućih modula 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- import shell/1 from shell. % za shell(cls/clear) -> "čišćenje" ekrana
:- import random/3 from random. % za nasumični odabir
:- import length/2 from lists. % za određivanje duljine liste
:- import append/3 from lists. % za spajanje lista
:- import last/2 from lists. % za dohvat zadnjeg elementa liste
:- import nth/3 from lists. % za dohvat nth-og elementa liste
:- import max_list/2 from lists. % za određivanje maksimalnog elementa liste
:- import findall/3 from setof. % za pronalazak svih rješenja

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Definicija dinamičkih predikata koji se mijenjaju tokom izvođenja
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- dynamic brojPobjeda/1. % za evidenciju pobjeda čovjeka
:- dynamic brojNerijesenih/1. % za evidenciju broja neriješenih partija
:- dynamic brojIzgubljenih/1. % za evidenciju broja izgubljenih
:- dynamic odigraneGeste/1. % za evidenciju odigranih gesti
:- dynamic vjerojatniPotezi/1. % za spremanje vjerojatnih poteza

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Predikati za inkrementiranje brojača 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
uvecajBrojPobjeda :- retract(brojPobjeda(BrojPobjeda)), % dohvaća br. pobjeda
	NoviBrojPobjeda is BrojPobjeda + 1, % uvećava ga za jedan
	assert( brojPobjeda( NoviBrojPobjeda ) ). % upis u dinamički predikat 

uvecajBrojNerijesenih :- retract( brojNerijesenih( BrojNerijesenih )), 
	NoviBrojNerijesenih is BrojNerijesenih + 1,
	assert( brojNerijesenih( NoviBrojNerijesenih ) ). 
	
uvecajBrojIzgubljenih :- retract( brojIzgubljenih( BrojIzgubljenih )),
	NoviBrojIzgubljenih is BrojIzgubljenih + 1,
	assert( brojIzgubljenih( NoviBrojIzgubljenih )). 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Rad s listama, dodavanje elementa u listu
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%	dodajGestu/1
%	Dodavanje odigrane geste u listu odigranih gesti
%%% 1 	dohvaća listu odigranih gesti,
%%% 2	dodaje gestu na početak dohvaćene liste,
%%%	3	spremanje nove liste u dinamički predikat odigraneGeste/1
%
dodajGestu( Gesta ) :- retract( odigraneGeste( ListaOdigranihGesti )),
	NovaListaOdigranihGesti = [Gesta|ListaOdigranihGesti],
	assert( odigraneGeste( NovaListaOdigranihGesti )).

%%
%	dodajVjerojatniPotez/1
%	Dodavanje vjerojatnog poteza igrača u listu vjerojatnih poteza
%%% 1	dohvaća listu vjerojatnih poteza
%%% 2 	dodaje potez na početak dohvaćene liste
%%% 3	spremanje nove liste u dinamički predikat vjerojatniPotezi/1
%
dodajVjerojatniPotez( Potez ) :- 
	retract( vjerojatniPotezi(ListaVjerovatnihPoteza )), 
	NovaListaPoteza = [Potez|ListaVjerovatnihPoteza], 
	assert( vjerojatniPotezi( NovaListaPoteza )). 
	
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
%% Činjenice
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%	Činjenice za potrebe provjere geste (upisa) igrača u RPSLS
% 
gesta( kamen ).
gesta( papir ).
gesta( skare ).
gesta( guster ).
gesta( spock ).

%%
%	Činjenice za potrebe provjere geste (upisa) igrača u RPS
% 
gestaRPS( kamen ).
gestaRPS( papir ).
gestaRPS( skare ).

%%
%	jaci/2
% 	jaci( ?jacaGesta, ?slabijaGesta )
%	Predikat je istinit ako je na prvom mjesti jača gesta
%	a na drugom slabija
%
jaci( kamen, skare).
jaci( kamen, guster).

jaci( papir, kamen ).
jaci( papir, spock ).

jaci( skare, papir ).
jaci( skare, guster ).

jaci( guster, papir ).
jaci( guster, spock ).

jaci( spock, kamen ).
jaci( spock, skare ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
%% Pravila
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%	pobjednik/3
%	pobjednik( ?gesta1, ?gesta2, ?rezultat )
%
pobjednik( X, X, nerijeseno ).
pobjednik( X, Y, X ) :- jaci( X, Y ).
pobjednik( X, Y, Y ) :- jaci( Y, X ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
%% Ispis rezultata
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%	tuce/2
%	tuce( ?gestaPobjednik, ?gestaGubitnik )
% 	Za ispis ishoda partije odnosno koja je gesta jača
%
tuce(Pobjednik, Gubitnik) :- Pobjednik == skare, Gubitnik == papir, 
	write(Pobjednik), write(' REZU '), write(Gubitnik), !. 
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == papir, Gubitnik == kamen, 
	write(Pobjednik), write(' PREKRIVA '), write(Gubitnik), !.
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == kamen, Gubitnik == guster, 
	write(Pobjednik), write(' GNJECI '), write(Gubitnik), write('a'), !.
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == guster, Gubitnik == spock, 
	write(Pobjednik), write(' TRUJE '), write(Gubitnik), write('a'), !.
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == spock, Gubitnik == skare, 
	write(Pobjednik), write(' TRGA '), write(Gubitnik), !.    
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == skare, Gubitnik == guster, 
	write(Pobjednik), write(' REZU GLAVU '), write(Gubitnik), write('u'), !.
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == guster, Gubitnik == papir, 
	write(Pobjednik), write(' JEDE '), write(Gubitnik), !.
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == papir, Gubitnik == spock, 
	write(Pobjednik), write(' POBIJA '), write(Gubitnik), write('a'), !. 
	
tuce(Pobjednik, Gubitnik) :- Pobjednik == spock, Gubitnik == kamen, 
	write(Pobjednik), write(' PRETVARA '), 
	write(Gubitnik), write(' U PRAH'), !.

tuce(Pobjednik, Gubitnik) :- Pobjednik == kamen, Gubitnik == skare, 
	write(Pobjednik), write(' DROBI '), write(Gubitnik), !.   

%%
%	ispisPobjednika/3
%	ispisPobjednika( potezCovjeka, potezRacunala, Pobjednik/nerijeseno )
%	Ispis pobjednika partije te inkrementiranje odgovarajućeg brojača
%
ispisPobjednika( _, _, nerijeseno ) :- nl, nl, write('Ishod: '), 
	write('-> Nerijeseno!'), uvecajBrojNerijesenih, nl.
	
ispisPobjednika( Gub, Pob, Pob ) :- nl, nl, write('Ishod: '), tuce(Pob, Gub),
	nl, write('-> Racunalo1 je pobjednik!'), uvecajBrojIzgubljenih, nl. 
	
ispisPobjednika( Pob, Gub, Pob ) :- nl, nl, write('Ishod: '), tuce(Pob, Gub),
	nl, write('--> Vi ste pobjednik!'), uvecajBrojPobjeda, nl. 

%%
%	ispisPobjednikaSim/3
%	ispisPobjednika( potezRacunala1, potezRacunala2, Pobjednik/nerijeseno )
%	Ispis pobjednika kod funkcionalnosti simulacije partija između računala
%
ispisPobjednikaSim( _, _, nerijeseno ) :- nl, nl, write('Ishod: '), 
	write('-> Nerijeseno!'), uvecajBrojNerijesenih, nl.
	
ispisPobjednikaSim( Gub, Pob, Pob ) :- nl, nl, write('Ishod: '), 
	tuce(Pob, Gub), nl, write('-> Racunalo1 je pobjednik!'), 
	uvecajBrojIzgubljenih, nl. 
	
ispisPobjednikaSim( Pob, Gub, Pob ) :- nl, nl, write('Ishod: '), 
	tuce(Pob, Gub), nl, write('-> Racunalo2 je pobjednik!'), 
	uvecajBrojPobjeda, nl. 

%%
%	izracunPobjednika3/3
%	izracunPobjednika3( potezCovjeka, potezRacunala1, potezRacunala2 )
%	Izračun i ispis pobjednika kod igre s 3 igrača.
%%% alg->	Ako su dva igrača odigrali različite geste provjerava se, 
%%%			evidentira i ispisuje, koja je jača (ishodi partija).
%%% 		Nerijeseni ishodi se ne računaju/zapisuju.
%%%			Broj pobjeda Racunala2 se sprema na način na koji se u igri 
%%%			sa dva igrača spremaju neriješeni ishodi.
%
izracunPobjednika3(X, Y, Z) :- 
	(X \= Y -> (pobjednik(X, Y, X) -> nl, nl, write('Ishod: '), tuce(X, Y),
		nl, write('--> Vi ste pobijedili Racunalo1'), uvecajBrojPobjeda, 
		nl; nl, nl, write('Ishod: '), tuce(Y, X), nl, 
		write('--> Racunalo1 je pobijedilo Vas'), 
		uvecajBrojIzgubljenih, nl);true),
	(X \= Z -> (pobjednik(X, Z, X) -> nl, nl, write('Ishod: '), tuce(X, Z), 
		nl, write('--> Vi ste pobijedili Racunalo2'), uvecajBrojPobjeda, 
		nl; nl, nl, write('Ishod: '), tuce(Z, X), nl, 
		write('--> Racunalo2 je pobijedilo Vas'), 
		uvecajBrojNerijesenih, nl);true),
	(Y \= Z -> (pobjednik(Y, Z, Y) -> nl, nl, write('Ishod: '), tuce(Y, Z),
		nl, write('--> Racunalo1 je pobijedilo Racunalo2'), 
		uvecajBrojIzgubljenih, nl; nl, nl, write('Ishod: '), tuce(Z, Y), nl, 
		write('--> Racunalo2 je pobijedilo Racunalo1'), 
		uvecajBrojNerijesenih, nl);true). 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%	
%% Predviđanje poteza igrača
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%	brojOdigranihPoteza/1
%	brojOdigranihPoteza( ?BrojOdigranihPoteza)
%	Za dobivanje broja odigranih poteza na temelju liste odigranih gesti
%
brojOdigranihPoteza( BrojPoteza ) :- odigraneGeste(ListaOdigranihGesti), 
	length(ListaOdigranihGesti, BrojPoteza).

%%
%	prvih_n/3
%	Predikat prvih_n( L, N, P ) je istinit ukoliko je P lista prvih 
%	N članova iz liste L.
%	Preuzeto sa http://autopoiesis.foi.hr/wiki.php?name=Logi%C4%8Dko%20pro
%	gramiranje%20-%20FOI&parent=NULL&page=liste
%	Za dobivanje prvih n članova liste odigranih gesti odnosno patterna za 
%	analizu ostalih gesti i predviđanje vjerojatnog poteza
%
prvih_n( L, N, P ) :-
    prvih_n( L, N, [], P ).
prvih_n( _, 0, P, P ).
prvih_n( [ G | R ], N, P, L ) :-
    N1 is N - 1,
    prvih_n( R, N1, P, L1 ),
    L = [ G | L1 ].
	
%%
%	predvidiMoguciPotezIgraca/3
%	Predikat koji na temelju Liste odigranih gesti i liste 
%	TrazeniPattern predviđa Moguci potez koji bi korisnik mogao odigrati
%	
predvidiMoguciPotezIgraca(ListaOdigranihGesti, TrazeniPattern, MoguciPotez):- 
	% TrazeniPattern je Pattern na temelju kojeg se provodi analiza
    append( DioListeDoPatterna, OstatakListeDoKraja, ListaOdigranihGesti ), 
	% DioListeDoPatterna + OstatakListeDoKraja = ListaOdigranihGesti
	append( TrazeniPattern, _DioListePoslijePatterna, OstatakListeDoKraja ), 
	% TrazeniPattern + _DioListePoslijePatterna = OstatakListeDoKraja
    length( DioListeDoPatterna, DuljinaPrefiksa ), 
	% računanje duljine liste prije patterna 
	(DuljinaPrefiksa is 0 -> MoguciPotez = na; 
	last( DioListeDoPatterna, MoguciPotez )). 
	% ako je duljina 0, vjerojatnog poteza nema, inače vjerojatni potez je 
	% zadnji element liste do patterna

%%
%	moguciPoteziIgraca/2
%	Za dobivanje liste mogućih poteza igrača, na temelju prethodno 
%	odigranih rundi (partija) te duljine patterna
%		
moguciPoteziIgraca( ListaMogucihPoteza, DuljinaPatterna ) :- 
	odigraneGeste( ListaGesti ), % dohvaćanje do sada odigranih gesti
	prvih_n( ListaGesti, DuljinaPatterna, PrvihN ), 
	% lista PrvihN sadrži pattern duljine DuljinaPatterna koji
	% se nalazi na početku liste ListaGesti
	findall( _X, predvidiMoguciPotezIgraca( ListaGesti, PrvihN, _X),
	ListaMogucihPoteza ). % pattern PrvihN koristi se za traženje mogućih 
	% poteza protivnika te spremanje istih u ListaMOgucihPoteza

%%
%	broji/3
%	broji( ?Gesta, Lista, ?Broj)
%	Za brojanje koliko se puta određena gesta nalazi u Listi
%	
broji(_, [], 0) :- !. % broj elemenata prazne liste je 0

broji(X, [X|R], N) :- % ako se gesta nalazi u glavi liste
    broji(X, R, N2), % provjeri rep sa Broj je Broj2
    N is N2 + 1. % kad se gesta nalazi u glavi liste Broj je Broj2 + 1 

broji(X, [Y|R], N) :- 
    X \= Y,          % ako se gesta ne nalazi u glavi liste
    broji(X, R, N).  % bez ikakvog povećanja brojača, provjeri rep liste
	
%%
%	listaVjerojatnihPoteza/1
%	Predikat koji dodaje vjerojatne poteze igrača listi vjerojatnih poteza
%	Vjerojatni potez je gesta koja se najviše puta javlja u 
%	listi mogućih poteza
%	Kako se u listi mogućih poteza može javiti više razčičitih gesti 
%	maksimalan broj puta geste je potrebno spremiti u listu te 
%	zatim ovisno o broju odabrati vjerojatni potez
%	
listaVjerojatnihPoteza( DuljinaPatterna ) :- 
	moguciPoteziIgraca( ListaMogucihPoteza, DuljinaPatterna), 
	% dohvaćaju se mogući potezi igrača i za svaku moguću gestu se 
	% broji broj pojavljivanja te geste u listi mogućih poteza
	broji( kamen, ListaMogucihPoteza, BrojPojavljavanjaGesteKamen), 
	broji( papir, ListaMogucihPoteza, BrojPojavljavanjaGestePapir),
	broji( skare, ListaMogucihPoteza, BrojPojavljavanjaGesteSkare),
	broji( guster, ListaMogucihPoteza, BrojPojavljavanjaGesteGuster),
	broji( spock, ListaMogucihPoteza, BrojPojavljavanjaGesteSpock),
	
	% radi se lista koja se sastoji od brojeva koji predstvaljaju broj 
	% pojavljivanja određene geste u listi mogućih poteza te se u 
	% MaxBrojPojavljivanja zapisuje najveci broj pojavljivanja neke geste
	max_list([BrojPojavljavanjaGesteKamen, BrojPojavljavanjaGestePapir, 
		BrojPojavljavanjaGesteSkare, BrojPojavljavanjaGesteGuster, 
		BrojPojavljavanjaGesteSpock], MaxBrojPojavljivanja),
	
	% ako MaxBrojPojavljivanja nije 0 Na temelju patterna se moze zakljuciti 
	% o sljedećem potezu
	(not (MaxBrojPojavljivanja is 0) ->	
	% u listu vjerojatnih poteza se dodaju geste čiji broj pojavljivanja 
	% u listi mogucih poteza najveći
	(MaxBrojPojavljivanja == BrojPojavljavanjaGesteKamen -> 
		dodajVjerojatniPotez(kamen); true),
		
	(MaxBrojPojavljivanja == BrojPojavljavanjaGestePapir -> 
		dodajVjerojatniPotez(papir); true),
	
	(MaxBrojPojavljivanja == BrojPojavljavanjaGesteSkare -> 
		dodajVjerojatniPotez(skare); true),
	
	(MaxBrojPojavljivanja == BrojPojavljavanjaGesteGuster -> 
		dodajVjerojatniPotez(guster); true),
		
	(MaxBrojPojavljivanja == BrojPojavljavanjaGesteSpock -> 
		dodajVjerojatniPotez(spock); true); true).
	
%%
%	analizaPoteza/2
%	Predikat kojim se analizira lista vjerojatnih poteza na način
%	da se pozivaju predikati za predviđanje poteza
%	Ti predikati analiziraju do sadašnje poteze i predviđaju 
%	sljedeći potez
% 	Rezultati analize/predviđanja spremaju se u odgovarajuće liste
%	analiza poteza predikatu koji ga poziva daje informaciju o 
%	broju vjerojatnih poteza
%
analizaPoteza( DuljinaPatterna, BrojVjerojatnihPoteza ) :-	
	listaVjerojatnihPoteza( DuljinaPatterna ), 
	% kreiranje liste vjerojatnih poteza
	vjerojatniPotezi(ListaVjerojatnihPoteza), 
	% dohvaćanje liste vjerojatnih poteza
	length(ListaVjerojatnihPoteza, BrojVjerojatnihPoteza). 
	% računanje duljine te liste

%%
%	odabirKonkretnogPoteza/2
%	Predikat kojim se odabire konkretni potez za koji se, na temelju 
%	prethodnih poteza, zaključilo da bi igrač mogao odigrati
%
odabirKonkretnogPoteza(KonkretniPotez, BrojVjerojatnihPoteza) :-	
	GornjaGranica is BrojVjerojatnihPoteza + 1,
	random(1, GornjaGranica, RandBroj),
	vjerojatniPotezi(ListaVjerojatnihPoteza),
	nth(RandBroj, ListaVjerojatnihPoteza, KonkretniPotez), nl,
	write('Racunalo1 je predvidjelo da ce sljedeci potez biti: '), 
	write(KonkretniPotez), nl.
	
%%
%	vjerojatniPotezProtivnika/2
%	vjerojatniPotezProtivnika( ?VjerojatniPotez, TipIgre)
%	Predikat koji se koristi za donošenje odluke o vjerojatnom 
%	potezu protivnika
%	Odluka se donosi na temelju rezultat analize poteza i tipu igre (RPS ili 
%	RPSLS tk. 3 ili 5) o kojem ovisi koja je geste dozvoljeno odabrati 	
%
vjerojatniPotezProtivnika( Potez, TipIgre) :- 
	retractall(vjerojatniPotezi(_)), assert(vjerojatniPotezi( [] )), 
	% brisanje atoma dinamičkog predikata vjerojatniPotezi te 
	% spremanje prazne liste
	analizaPoteza( 4, BVP4), % radi se analiza poteza, DuljinaPatterna 
	% je postavljena na 4 te se dobija info o broju vjerojatnih poteza BVP4
	% kada se koristi pattern duljine 4, ako je je BVP nula radi se analiza
	% sa patternom koji je jednu gestu kraći
	% ako je BVP 0 za pattern dulj. 1, vjerojatni potez se izabire nasumično
	(BVP4 == 0 -> analizaPoteza( 3, BVP3),
	(BVP3 == 0 -> analizaPoteza( 2, BVP2), 
	(BVP2 == 0 -> analizaPoteza( 1, BVP1), 
	(BVP1 == 0 -> nl, 
	write('Racunalo1 nije uspjelo predvidjeti sljedeci potez!'), 
	nl, nasumicniOdabirPoteza(Potez, TipIgre);
	odabirKonkretnogPoteza(Potez, BVP1));
	odabirKonkretnogPoteza(Potez, BVP2));
	odabirKonkretnogPoteza(Potez, BVP3));
	odabirKonkretnogPoteza(Potez, BVP4)).
	
%%
%	nasumicniOdabirPoteza/2
%	Predikat koji se poziva za nasumični odabir poteza odnosno slučaj kada 
%	se potez ne može predvidjeti algoritmom	
%
nasumicniOdabirPoteza( Potez, TipIgre ) :- random(0, TipIgre, Broj), 
	% TipIgre je gornja granica koja ovisi o tipu RPS ili RPSLS (3 ili 5)
	(Broj is 0 -> Potez = kamen; (Broj is 1 -> Potez = papir; 
	(Broj is 2 -> Potez = skare; (Broj is 3 -> Potez = spock; 
	(Broj is 4 -> Potez = guster))));true).

%%	
%	clear/0
% 	Predikat koji poziva shell(cls),
%	shell naredbu za čišćenje ekrana
%	Pažnja: u slučaju de se program pokreće na unixu, potrebno je promijeniti
%	shell(cls) u shell(clear)
%
clear :- shell(cls). % na unix os-u -> shell(clear).

%%
%	restart/0 -> retractall/1, assert/1
%	Predikat koji se poziva za brisanje i inicijalizaciju dinamičkih predikata 	
%
restart :- retractall(brojPobjeda(_)), retractall(brojNerijesenih(_)), 
	retractall(brojIzgubljenih(_)), retractall(odigraneGeste(_)), 
	retractall(vjerojatniPotezi(_)), assert(brojPobjeda( 0 )), 
	assert(brojNerijesenih( 0 )), assert(brojIzgubljenih( 0 )), 
	assert(odigraneGeste( [] )), assert(vjerojatniPotezi( [] )). 

%%	
%	izbornik/0
%	Za ispis izbornika sa dostupnim opcijama
%
izbornik :- clear, oProgramu, 
	writeln('Izbor igre: '), nl,
	writeln(' -> a. RPSLS 2 Igraca < Vi vs. R1[smart] >'), nl, 
	writeln(' -> b. RPSLS 3 Igraca < Vi vs. R1[smart] vs. R2[rand] >'), nl,
	writeln(' -> c. RPSLS Simulacija 2 igraca < R1[smart] vs. R2[rand] >'), 
	nl, writeln(' -> d. RPS 2 Igraca < Vi vs. R1[smart] >'), nl,
	writeln(' -> e. Izlaz iz igre'), nl,
	write('Izbor: '), catch( read( Izbor ), _, (
	nl, write('Sintaksa upisanog odabira nije ispravna!'), izbornik)),
	(Izbor == 'a' -> restart, naredbeRPSLS, rpsls;
	(Izbor == 'b' -> restart, naredbeRPSLS3, rpsls3;
	(Izbor == 'c' -> restart, rpslsSimulacija;
	(Izbor == 'd' -> restart, naredbeRPS, rps;
	(Izbor == 'e' -> izlaz; call(izbornik)))))).
:- izbornik.

%%
%	rpsls/0
%	Za pozivanje igre RPSLS između čovjeka i računala koje 
%	svoj potez u prvih 5 rundi vrši nasumično a nakon toga na 
%	temelju prethodno odigranih poteza
%
rpsls :- brojOdigranihPoteza( BrOdigranihPoteza ), 
	%dohvaćanje broja odigranih poteza
	BrOdigranihRundi is BrOdigranihPoteza + 1, % za ispis broja rundi
	nl, write('Runda '), write( BrOdigranihRundi ),
	write(' **********************************************************************'),
	nl, nl, write( 'Vas potez: ' ),
	% čita korisnikovu naredbu/potez i provjerava da li je sintaksa 
	% upisanog ispravna
	catch( read( X ), _, (nl, write('Sintaksa upisane naredbe nije ispravna!'),
	nl, nl,write('Molimo ponovite potez koristeci jednu od ispravnih naredbi.'),
	nl, naredbeRPSLS, rpsls)),
	% ako je upisana gesta, računalo odigrava svoj potez
	( gesta( X ) -> 
		(BrOdigranihPoteza > 4 -> vjerojatniPotezProtivnika( Potez, 5 ), 
			random( 1,3, RandOdabir ), % ako je br odigranih poteza veći od 4 
			% (br odigranih rundi > 5)
			(Potez == kamen -> nth(RandOdabir, [papir, spock], Y); 
			(Potez == papir -> nth( RandOdabir, [skare, guster], Y ); % radi 
			% se analiza vjerojatnog poteza te ovisno o rezultatu racunalo 
			% odigrava svoj
			(Potez == skare -> nth(RandOdabir, [kamen, spock], Y); 
			(Potez == guster -> nth( RandOdabir, [kamen, skare], Y ); % nakon 
			% utvrđivanja vjerojatnog poteza nasumicno se odabire onaj koji 
			% je jaci od te geste
			(Potez == spock -> nth(RandOdabir, [papir, guster], Y)))))); 
			nasumicniOdabirPoteza( Y, 5 )),	% u slučaju kad je runda < od 5, 
			% računalo nasumično odabire potez
	pobjednik( X, Y, Rez ), nl,write('Racunalo1: '), write( Y ), write('.'),
	ispisPobjednika( X, Y, Rez ), % ispis poteza računala, računanje 
	% i ispis pobjenika
	ispisTrenutnogRezultata,dodajGestu( X ); % ispis rezultata partija, 
	% odigrana gesta se dodaje u listu odigranih gesti
	(X == izb -> izbornik; % ako je naredba izb. poziva se izbornik
	(X == nar -> naredbeRPSLS; % ako je naredba nar. ispisuju se naredbe
	(X == log -> odigraneGeste( G ), nl, write('Lista odigranih gesti: '), 
	write( G ), nl; % ako je naredba log. ipisuje se lista odigranih gesti
	nl, write('Paznja! "'), write( X ), write('." nije valjana naredba!'), 
	nl, naredbeRPSLS)))), % ako upisana naredba nije valjana/dozvoljena, 
	% ispisuje se lista naredbi
	rpsls. % ponovno pozivanje rpsls

%%
%	rps/0
%	Za pozivanje igre RPS između čovjeka i računala koje 
%	svoj potez u prvih 5 rundi vrši nasumično a nakon toga na 
%	temelju prethodno odigranih poteza
%	
rps :- brojOdigranihPoteza( BrOdigranihPoteza ),
	BrOdigranihRundi is BrOdigranihPoteza + 1,
	nl, write('Runda '), write(BrOdigranihRundi), 
	write(' **********************************************************************'),
	nl, write( 'Vas potez: ' ),
	% čita korisnikovu naredbu/potez i provjerava da li je sintaksa 
	% upisanog ispravna
	catch( read( X ), _, (nl, 
		write('Sintaksa upisane naredbe nije ispravna!'), nl, nl,
		write('Molimo ponovite potez koristeci jednu od ispravnih naredbi.'),
		nl, naredbeRPS, rps)),
	(gestaRPS( X ) -> 
		(BrOdigranihPoteza > 4 -> vjerojatniPotezProtivnika( Potez, 3 ),
			(Potez == kamen -> Y = papir; (Potez == papir -> Y = skare; 
			(Potez == skare -> Y = kamen; true))); 
			nasumicniOdabirPoteza( Y, 3 )),
	pobjednik( X, Y, Rez ), nl, write('Racunalo1: '), write(Y), write('.'), 
	ispisPobjednika( X, Y, Rez ),
	ispisTrenutnogRezultata, dodajGestu( X ); 
	(X == izb -> izbornik; % ako je naredba izb. poziva se izbornik
	(X == nar -> naredbeRPS; % ako je naredba nar. ispisuju se naredbe
	(X == log -> odigraneGeste( G ), nl, write('Lista odigranih gesti: '), 
	write( G ), nl; % ako je naredba log. ipisuje se lista odigranih gesti
	nl, write('Paznja! "'), write( X ), write('." nije valjana naredba!'), nl, 
	naredbeRPS)))), % ako upisana naredba nije valjana/dozvoljena,
	% ispisuje se lista naredbi
	rps. %ponovno se poziva rps

%%
%	rpsls3/0
%	Za pozivanje igre RPSLS između čovjeka i 2 računala, Računala1 koje 
%	svoj potez u prvih 5 rundi vrši nasumično a nakon toga na temelju prethodno 
%	odigranih poteza i Računala 2 koje svoje poteze vuče nasumično
%	
rpsls3 :- brojOdigranihPoteza( BrOdigranihPoteza ), %dohvaćanje 
	% broja odigranih poteza
	BrOdigranihRundi is BrOdigranihPoteza + 1,
	nl, write('Runda '), write(BrOdigranihRundi),
	write(' **********************************************************************'), 
	nl, write( 'Vas potez: ' ),
	% čita korisnikovu naredbu/potez i provjerava da li je sintaksa ispravna
	catch( read( X ), _, (nl, write('Sintaksa upisane naredbe nije ispravna!'),
	nl, nl, % ako nije ispisuje se poruka te ponavlja runda
	write('Molimo ponovite potez koristeci jednu od ispravnih naredbi.'), nl,
	naredbeRPSLS3, rpsls3)),
	( gesta( X ) -> 
		(BrOdigranihPoteza > 4 -> vjerojatniPotezProtivnika(Potez, 5), 
			random(1,3, RandOdabir),
			(Potez == kamen -> nth(RandOdabir, [papir, spock], Y); 
			(Potez == papir -> nth(RandOdabir, [skare, guster], Y);
			(Potez == skare -> nth(RandOdabir, [kamen, spock], Y); 
			(Potez == guster -> nth(RandOdabir, [kamen, skare], Y);
			(Potez == spock -> nth(RandOdabir, [papir, guster], Y)))))); 
			nasumicniOdabirPoteza( Y, 5 )), nasumicniOdabirPoteza( Z, 5 ),
	nl, write('Racunalo1: '), write(Y), write('.'),
	nl, nl, write('Racunalo2: '), write(Z), write('.'), 
	izracunPobjednika3( X, Y, Z ), ispisTrenutnogRezultata3, dodajGestu( X ); 
	% gesta se dodaje u listu odigranih gesti
	(X == izb -> izbornik; % ako je naredba izb. poziva se izbornik
	(X == nar -> naredbeRPSLS3; % ako je naredba nar. ispisuju se naredbe
	(X == log -> odigraneGeste( G ), nl, write('Lista odigranih gesti: '), 
	write( G ), nl; % ako je naredba log. ipisuje se lista odigranih gesti
	nl, write('Paznja! "'), write( X ), write('." nije valjana naredba!'),
	nl, naredbeRPSLS3)))), % ipis poruke i listi naredbi
	rpsls3. % ponovno se poziva rpsls3
	
%%
%	simulacijaJednePartije/1
%	Za simulaciju jedne partije odnosno odabir poteza računala i ispis rezultata
%	Proslijeđeni parametar BrRunde koristi se za točan ispis 
%	broja runde koja se odigrava
%		
simulacijaJednePartije( BrRunde ) :-
	nl, write('Runda '), write(BrRunde),
	write(' **********************************************************************'),
	nl, nasumicniOdabirPoteza( X, 5 ), % R2 nasumično odabire potez
	(BrRunde > 5 -> vjerojatniPotezProtivnika(Potez, 5), 
		random(1,3, RandOdabir), % odabir jače geste od predviđene protivnikove
		(Potez == kamen -> nth(RandOdabir, [papir, spock], Y); 
		(Potez == papir -> nth(RandOdabir, [skare, guster], Y);
		(Potez == skare -> nth(RandOdabir, [kamen, spock], Y); 
		(Potez == guster -> nth(RandOdabir, [kamen, skare], Y);
		(Potez == spock -> nth(RandOdabir, [papir, guster], Y)))))); 
			nasumicniOdabirPoteza( Y, 5 )), % ako je broj rundi <= 5
	pobjednik( X, Y, Rez ), nl, write('Racunalo1: '), write(Y), write('.'), 
	nl, nl, write('Racunalo2: '), write(X), write('.'), 
	ispisPobjednikaSim( X, Y, Rez ), ispisTrenutnogRezultataSim, 
	dodajGestu( X ). % dodaje se odigrana gesta od računala 2 u listu odigranih gesti	
%%
%	simulacijaPartija/1
%	Za simulaciju partija između računala 1 i računala 2
%	Proslijeđeni parametar BrojPartija koristi se za utvrđivanje 
%	koliko partija je potrebno simulirati (kada stati sa simulacijom)
%	
simulacijaPartija( BrojPartija ) :- brojOdigranihPoteza( BrOdigranihPoteza ), 
	%dohvaćanje broja odigranih poteza
	BrOdigranihRundi is BrOdigranihPoteza + 1,
	(BrOdigranihRundi =< BrojPartija ->
		simulacijaJednePartije( BrOdigranihRundi ); naredbeSim),
	simulacijaPartija( BrojPartija ).

%%
%	rpslsSimulacija
%	Za pozivanje simulacije igre između računala 1 i računala 2
%	Korisnik upisuje koliko partija želi simulirati te se na temelju
%	tog broja poziva predikat simulacijaPartija
%		
rpslsSimulacija :- restart, write( 'Broj partija: ' ),
	catch( read( BrojPartija ), _, 
	(nl, write('Sintaksa upisanog nije ispravna!'), nl, nl,
	write('Molimo upisite broj partija s kojim zelite pokrenuti simulaciju'),
	nl, nl, rpslsSimulacija)),
	(number(BrojPartija) -> simulacijaPartija( BrojPartija );
	write('Molimo upisite broj!'), nl, rpslsSimulacija).

%%
%	izlaz/0
%	Za izlaz iz programa, nakon pozivanja ovog predikata radi se upit da li se
%	zaista želi izaći, te ovisno o odgovoru poziva halt. ili izbornik.	
%
izlaz :- write('Da li stvarno zelite izaci?'), nl, write('--> d.'), nl, 
	write('--> n.'), nl, write('Izbor: '), catch( read( X ), _, izlaz), 
	( X == 'd' -> halt; ( X == 'n' -> izbornik; call(izlaz))).

%%
%	ispisTrenutnogRezultata/0
%	Za ispis trenutnog rezultata u igri RPSLS sa 2 igrača čovjek vs. Računalo 1 i igri RPS
%
ispisTrenutnogRezultata :- nl,
	write('Trenutni rezultat:\n\tBroj Vasih pobjeda: '), brojPobjeda( BP ), 
	write( BP ), nl, write('\tBroj nerijesenih: '), brojNerijesenih( BN ), 
	write( BN ), nl, write('\tBroj pobjeda racunala: '), brojIzgubljenih( BI ),
	write( BI ), nl.
	
%%
%	ispisTrenutnogRezultata3/0
%	Za ispis trenutnog rezultata u igri RPSLS 3 igrača
%
ispisTrenutnogRezultata3 :- nl,
	write('Trenutni rezultat:\n\tBroj Vasih pobjeda: '), brojPobjeda( BP ), 
	write( BP ), nl, write('\tBroj pobjeda racunala1: '), brojIzgubljenih( BI ),
	write( BI ), nl, write('\tBroj pobjeda Racunala2: '), brojNerijesenih( BN ),
	write( BN ), nl.

%%
%	ispisTrenutnogRezultataSim/0
%	Za ispis trenutnog rezultata u simulaciji igre RPSLS
%
ispisTrenutnogRezultataSim :- nl,
	write('Trenutni rezultat:\n\tBroj pobjeda racunala1: '), 
	brojIzgubljenih( BI ), write( BI ), nl, 
	write('\tBroj nerijesenih: '), brojNerijesenih( BN ), 
	write( BN ), nl, write('\tBroj pobjeda Racunala2: '), 
	brojPobjeda( BP ), write( BP ), nl.
	
%%	
%	oProgramu/0
%	Za ispis informacija o programu
%
oProgramu :- writeln('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'),
	writeln('%%'),
	writeln('% Igra: Kamen-Papir-Skare-Guster-Spock'),
	writeln('% Autor: Josip Zemberi'),
	writeln('% Fakultet organizacije i informatike Varazdin'),
	writeln('% Kolegij: Logicko programiranje'),
	writeln('%%'),
	writeln('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'), nl,
	writeln('+ Racunalo1[smart]... za poteze koristi pattern recognition algoritam'),
	writeln('+ Racunalo2[rand]... za poteze koristi funkciju rand'), nl,
	writeln('-------------------------------------------------------------------------------'), nl.

%%	
%	naredbeRPS/0
%	Za ispis dostupnih naredbi u igri RPS
%
naredbeRPS :- nl, write('Igra: RPS 2 Igraca < Vi vs. R1[smart] >'), nl, nl, 
	write('Naredbe: kamen. | papir. | skare. | log. | nar. | izb.'), nl.

%%	
%	naredbeRPSLS/0
%	Za ispis dostupnih naredbi u igri RPSLS
%
naredbeRPSLS :- nl, write('Igra: RPSLS 2 Igraca < Vi vs. R1[smart] >'), nl, nl, 
	write('Naredbe: kamen. | papir. | skare. | guster. | spock. | log. | nar. | izb.'), nl.

%%	
%	naredbeRPSLS3/0
%	Za ispis dostupnih naredbi u igri RPSLS sa tri igrača
%
naredbeRPSLS3 :- nl, write('Igra: RPSLS 3 Igraca < Vi vs. R1[smart] vs. R2[rand] >'), nl, nl, 
	write('Naredbe: kamen. | papir. | skare. | guster. | spock. | log. | nar. | izb.'), nl.
	
%%	
%	naredbeSim/0
%	Za ispis dostupnih naredbi u simulaciji igre između dva računala
%	
naredbeSim :- nl, write('Naredbe: nova. | log. | izb.'), nl, write('Izbor: '), read(X), 
	(X == izb -> izbornik; (X == log -> odigraneGeste(G), nl, 
	write('Lista odigranih gesti od strane Racunalo2: '), write(G), nl;
	(X == nova -> rpslsSimulacija; naredbeSim))).
	
