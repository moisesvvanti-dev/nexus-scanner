import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.21.0'

// Essa é a chave de acesso total (Bypass de RLS) - NUNCA ENVIADA PARA O FRONTEND
const supabaseAdmin = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
)

serve(async (req) => {
    // CORS Headers
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: { 'Access-Control-Allow-Origin': '*' } })
    }

    try {
        // 1. OBRIGATÓRIO: Validar o JWT do usuário que fez a requisição
        const authHeader = req.headers.get('Authorization')!
        const token = authHeader.replace('Bearer ', '')
        const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token)

        if (authError || !user) {
            return new Response(JSON.stringify({ error: 'Não autorizado' }), { status: 401 })
        }

        // 2. Extrair dados da transação do corpo da requisição
        const body = await req.json()
        const amountToAdd = parseFloat(body.amount)

        // 3. Sanitização de Input: Evita valores negativos, Strings SQL Injection e valores absurdos
        if (isNaN(amountToAdd) || amountToAdd <= 0 || amountToAdd > 10000) {
            return new Response(JSON.stringify({ error: 'Valor de depósito inválido.' }), { status: 400 })
        }

        // 4. Execução da Função RPC no Banco de Dados (Operação Atômica Anti-Race Condition)
        // O backend CHAMA o RPC que foi configurado para resolver locks, então o código JS não calcula o saldo.
        const { data, error } = await supabaseAdmin.rpc('add_funds_atomically', {
            user_id_param: user.id,
            amount_param: amountToAdd
        })

        if (error) throw error

        return new Response(JSON.stringify({ success: true, new_balance: data }), {
            headers: { 'Content-Type': 'application/json' },
            status: 200
        })

    } catch (error) {
        console.error("Erro na transação:", error.message)
        // Anti-Info Leak: Mensagem de erro genérica retornada ao frontend
        return new Response(JSON.stringify({ error: 'Erro interno ao processar a transação financeira.' }), {
            status: 500
        })
    }
})
