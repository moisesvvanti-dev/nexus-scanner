-- 1. Tabela de Perfil/Carteira
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID REFERENCES auth.users(id) PRIMARY KEY,
    email TEXT,
    balance NUMERIC DEFAULT 0.00 CHECK (balance >= 0) -- Constraint no nível do banco para nunca ficar negativo
);

-- 2. Ativar Row Level Security (RLS)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- 3. Apenas leitura liberada para o próprio usuário (Protege contra Info Leak / IDOR)
CREATE POLICY "Leitura apenas do próprio perfil" ON public.profiles FOR SELECT USING (auth.uid() = id);

-- 4. Bloqueio Completo de UPDATE pelo Client-Side!
-- O CLIENTE NÃO PODE ATUALIZAR O SEU PRÓPRIO SALDO NUNCA, NEM SEQUER ENVIANDO A REQUISIÇÃO.
CREATE POLICY "Bloquear Update do Frontend" ON public.profiles FOR UPDATE USING (false);

-- 5. Função RPC (Remote Procedure Call) Oculta - Processamento Atômico Anti Race-Condition
-- A função executa como "SECURITY DEFINER", o que significa que rola com privilégios de Admin 
-- ignorando a política "Bloquear Update do Frontend", mas SÓ O BACKEND (Edge Function com SERVICE ROLE) pode chamá-la de forma segura.
CREATE OR REPLACE FUNCTION add_funds_atomically(user_id_param UUID, amount_param NUMERIC)
RETURNS NUMERIC AS $$
DECLARE
    current_balance NUMERIC;
    new_balance NUMERIC;
BEGIN
    IF amount_param <= 0 THEN
        RAISE EXCEPTION 'Apenas valores positivos são permitidos.';
    END IF;

    -- [CRÍTICO] SELECT ... FOR UPDATE: Impede ataques de Race Condition ou Brute Force Hit.
    -- Se o sistema receber 50 comandos de depósito no mesmo milissegundo,
    -- o banco enfileira um a um de forma atômica para ler a linha, travar, somar e liberar.
    SELECT balance INTO current_balance 
    FROM public.profiles 
    WHERE id = user_id_param 
    FOR UPDATE;

    IF current_balance IS NULL THEN
        RAISE EXCEPTION 'Conta não encontrada para crédito.';
    END IF;

    -- Soma atômica
    new_balance := current_balance + amount_param;

    -- Update atômico seguro
    UPDATE public.profiles 
    SET balance = new_balance 
    WHERE id = user_id_param;

    RETURN new_balance;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
