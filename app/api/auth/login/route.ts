import { NextRequest, NextResponse } from 'next/server';
import { sanitizeString, checkRateLimit } from '@/lib/validation';
import { authenticateUser } from '@/lib/data/auth';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();

    // Input validation
    if (!username || !password) {
      return NextResponse.json(
        { error: 'Kullanıcı adı ve şifre gerekli' },
        { status: 400 }
      );
    }

    // Sanitize inputs
    const sanitizedUsername = sanitizeString(username.trim());
    
    // Rate limiting - max 5 attempts per minute per IP
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    if (!checkRateLimit(`login:${clientIp}`, 5, 60000)) {
      return NextResponse.json(
        { error: 'Çok fazla deneme. Lütfen 1 dakika bekleyin.' },
        { status: 429 }
      );
    }

    const auth = await authenticateUser(sanitizedUsername, password);

    if (auth.status === 'not_found') {
      return NextResponse.json({ error: 'Kullanıcı bulunamadı' }, { status: 401 });
    }
    if (auth.status === 'inactive') {
      return NextResponse.json({ error: 'Hesabınız devre dışı' }, { status: 403 });
    }
    if (auth.status === 'invalid_password') {
      return NextResponse.json({ error: 'Geçersiz şifre' }, { status: 401 });
    }
    if (auth.status !== 'ok') {
      return NextResponse.json(
        { error: 'Giriş başarısız', details: 'Auth error' },
        { status: 500 }
      );
    }

    const { payload, token } = auth;

    return NextResponse.json({
      success: true,
      user: {
        id: payload.id,
        username: payload.username,
        email: payload.email,
        role: payload.role
      },
      token
    });

  } catch (error) {
    console.error('Login hatası:', error);
    
    // Prisma bağlantı hatası kontrolü
    const errorMessage = error instanceof Error ? error.message : 'Bilinmeyen hata';
    
    if (errorMessage.includes('connect') || errorMessage.includes('Connection')) {
      console.error('Veritabanı bağlantı hatası:', errorMessage);
      return NextResponse.json(
        { error: 'Veritabanına bağlanılamadı. Lütfen daha sonra tekrar deneyin.' },
        { status: 503 }
      );
    }
    
    if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) {
      console.error('Veritabanı timeout hatası:', errorMessage);
      return NextResponse.json(
        { error: 'İşlem zaman aşımına uğradı. Lütfen tekrar deneyin.' },
        { status: 504 }
      );
    }
    
    return NextResponse.json(
      { error: 'Giriş başarısız. Lütfen tekrar deneyin.' },
      { status: 500 }
    );
  }
}

