package com.trollhunters.trollchat;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * TrollChat v2: chat directo con Trollhunters por internet vía Nostr.
 * Sin PC, sin cuentas, sin servidores propios: DMs cifrados NIP-04
 * a relays públicos. La identidad se genera en el primer arranque.
 */
public class MainActivity extends Activity {

    private static final String PREFS = "trollchat";
    private static final String K_PRIV = "privkey";

    // Pubkey del operador (Trollhunters en la VM). Los DMs van cifrados a esta clave.
    private static final String OPERATOR_PUB =
            "YOUR_OPERATOR_PUBKEY_HEX_HERE";

    private static final String[] RELAYS = new String[]{
            "wss://relay.damus.io",
            "wss://relay.primal.net",
            "wss://relay.snort.social"
    };

    private ListView lista;
    private EditText campo;
    private Button enviar;
    private TextView estado;
    private TextView aviso;
    private ChatAdapter adapter;
    private final java.util.List<Mensaje> mensajes = new java.util.ArrayList<>();

    private final Handler ui = new Handler(Looper.getMainLooper());
    private NostrClient nostr;
    private volatile boolean conectado = false;
    private String privHex;

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                        | View.SYSTEM_UI_FLAG_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION);

        privHex = prefs().getString(K_PRIV, null);
        if (privHex == null) {
            privHex = Secp256k1.bytesToHex(Secp256k1.generatePrivKey());
            prefs().edit().putString(K_PRIV, privHex).apply();
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0B0E14"));
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);

        // Encabezado: título + estado + ajustes
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        TextView titulo = new TextView(this);
        titulo.setText("TrollChat");
        titulo.setTextColor(Color.WHITE);
        titulo.setTextSize(28);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        head.addView(titulo, tlp);

        estado = new TextView(this);
        estado.setTextSize(18);
        head.addView(estado);

        Button ajustes = new Button(this);
        ajustes.setText("\u2699");
        ajustes.setTextSize(22);
        ajustes.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { mostrarInfo(); }
        });
        head.addView(ajustes);
        root.addView(head);

        // Lista de mensajes
        lista = new ListView(this);
        adapter = new ChatAdapter();
        lista.setAdapter(adapter);
        lista.setDivider(null);
        lista.setFocusable(true);
        LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        llp.setMargins(0, dp(8), 0, dp(8));
        root.addView(lista, llp);

        // Aviso
        aviso = new TextView(this);
        aviso.setText("Chat directo por internet. Sin PC de por medio.");
        aviso.setTextColor(Color.parseColor("#8A93A6"));
        aviso.setTextSize(15);
        aviso.setGravity(Gravity.CENTER);
        root.addView(aviso);

        // Fila de entrada: campo + enviar
        LinearLayout fila = new LinearLayout(this);
        fila.setOrientation(LinearLayout.HORIZONTAL);
        fila.setGravity(Gravity.CENTER_VERTICAL);

        campo = new EditText(this);
        campo.setHint("Escribe tu mensaje…");
        campo.setHintTextColor(Color.parseColor("#5A6378"));
        campo.setTextColor(Color.WHITE);
        campo.setTextSize(20);
        campo.setInputType(InputType.TYPE_CLASS_TEXT);
        campo.setImeOptions(EditorInfo.IME_ACTION_SEND);
        campo.setBackgroundColor(Color.parseColor("#1A2130"));
        campo.setPadding(dp(12), dp(12), dp(12), dp(12));
        campo.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override public boolean onEditorAction(TextView v, int actionId, KeyEvent e) {
                if (actionId == EditorInfo.IME_ACTION_SEND
                        || (e != null && e.getKeyCode() == KeyEvent.KEYCODE_ENTER
                            && e.getAction() == KeyEvent.ACTION_DOWN)) {
                    enviarMensaje();
                    return true;
                }
                return false;
            }
        });
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        clp.setMargins(0, 0, dp(8), 0);
        fila.addView(campo, clp);

        enviar = new Button(this);
        enviar.setText("Enviar");
        enviar.setTextSize(20);
        enviar.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { enviarMensaje(); }
        });
        fila.addView(enviar);
        root.addView(fila);

        setContentView(root);
        actualizarEstado();
        arrancarNostr();
    }

    @Override
    protected void onDestroy() {
        if (nostr != null) nostr.stop();
        super.onDestroy();
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    private void actualizarEstado() {
        if (conectado) {
            estado.setText("\u25CF Conectado");
            estado.setTextColor(Color.parseColor("#4ADE80"));
        } else {
            estado.setText("\u25CF Sin conexi\u00F3n");
            estado.setTextColor(Color.parseColor("#F87171"));
        }
    }

    private void arrancarNostr() {
        estado.setText("\u25CF Conectando\u2026");
        estado.setTextColor(Color.parseColor("#FBBF24"));
        nostr = new NostrClient(RELAYS, privHex, new NostrClient.Listener() {
            @Override public void onDm(final String sender, final String text, String eventId) {
                ui.post(new Runnable() {
                    @Override public void run() {
                        String de = OPERATOR_PUB.equals(sender) ? "Trollhunters" : "Desconocido";
                        mensajes.add(new Mensaje(de, text));
                        adapter.notifyDataSetChanged();
                        lista.setSelection(mensajes.size() - 1);
                    }
                });
            }
            @Override public void onConnectionChange(final boolean any) {
                ui.post(new Runnable() {
                    @Override public void run() {
                        conectado = any;
                        actualizarEstado();
                    }
                });
            }
        });
        nostr.start();
    }

    private void enviarMensaje() {
        final String texto = campo.getText().toString().trim();
        if (texto.isEmpty()) return;
        campo.setText("");
        mensajes.add(new Mensaje("juan", texto));
        adapter.notifyDataSetChanged();
        lista.setSelection(mensajes.size() - 1);
        if (nostr != null) nostr.sendDm(OPERATOR_PUB, texto);
        else toast("A\u00FAn no conectado, intenta de nuevo.");
    }

    private void toast(String t) {
        android.widget.Toast.makeText(this, t, android.widget.Toast.LENGTH_SHORT).show();
    }

    private void mostrarInfo() {
        String pub = nostr != null ? nostr.ownPubkey() : "?";
        LinearLayout lay = new LinearLayout(this);
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setPadding(dp(16), dp(16), dp(16), dp(16));

        TextView t1 = new TextView(this);
        t1.setText("Tu identidad en la red (clave pública):");
        t1.setTextSize(16);
        lay.addView(t1);

        TextView t2 = new TextView(this);
        t2.setText(pub);
        t2.setTextSize(13);
        t2.setTextColor(Color.parseColor("#7DD3FC"));
        t2.setPadding(0, dp(4), 0, dp(12));
        lay.addView(t2);

        TextView t3 = new TextView(this);
        t3.setText("Relays:\n\u2022 relay.damus.io\n\u2022 relay.primal.net\n\u2022 relay.snort.social\n\n"
                + "Los mensajes viajan cifrados directo por internet. El PC no interviene.");
        t3.setTextSize(15);
        lay.addView(t3);

        ScrollView sv = new ScrollView(this);
        sv.addView(lay);
        new AlertDialog.Builder(this)
                .setTitle("TrollChat v2 (Nostr)")
                .setView(sv)
                .setPositiveButton("Cerrar", null)
                .show();
    }

    private static class Mensaje {
        final String from;
        final String text;
        Mensaje(String from, String text) {
            this.from = from; this.text = text;
        }
    }

    private class ChatAdapter extends BaseAdapter {
        @Override public int getCount() { return mensajes.size(); }
        @Override public Object getItem(int p) { return mensajes.get(p); }
        @Override public long getItemId(int p) { return p; }

        @Override public View getView(int position, View convertView, ViewGroup parent) {
            Mensaje m = mensajes.get(position);
            LinearLayout row = new LinearLayout(MainActivity.this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(dp(12), dp(8), dp(12), dp(8));

            TextView quien = new TextView(MainActivity.this);
            TextView cuerpo = new TextView(MainActivity.this);
            cuerpo.setTextSize(20);
            cuerpo.setTextColor(Color.WHITE);

            boolean soyYo = "juan".equals(m.from);
            if (soyYo) {
                quien.setText("T\u00FA");
                quien.setTextColor(Color.parseColor("#7DD3FC"));
                row.setGravity(Gravity.END);
                cuerpo.setGravity(Gravity.END);
            } else {
                quien.setText(m.from);
                quien.setTextColor(Color.parseColor("#4ADE80"));
                row.setGravity(Gravity.START);
            }
            quien.setTextSize(14);
            cuerpo.setText(m.text);

            row.addView(quien);
            row.addView(cuerpo);
            return row;
        }
    }
}
