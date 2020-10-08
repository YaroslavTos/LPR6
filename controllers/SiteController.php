<?php

namespace app\controllers;

use Yii;
use yii\web\Response;
use yii\filters\VerbFilter;
use app\models\LoginForm;
use yii\web\UnauthorizedHttpException;

class SiteController extends BaseController
{

    public function behaviors()
{
    $behaviors = parent::behaviors();
    $behaviors['authenticator']['only'] = ['logout'];
    $behaviors['verbs'] = [
        'class' => VerbFilter::className(),
        'actions' => [
            'logout' => ['post'],
            'login' => ['post'],
        ],
    ];
    return $behaviors;
}



    public function actionIndex()
{
    return 'API for Shedule';
}



    public function actionLogin()
{
    $model = new LoginForm();
    $model->load(Yii::$app->request->bodyParams, '');
    if ($token = $model->auth()) {
        return $token;
    } else {
        throw new UnauthorizedHttpException('Unauthorized user');
    }
}



    public function actionLogout()
{
    if (Yii::$app->user->identity->logout()) {
        return ['message' => 'logout success'];
    }
    throw new UnauthorizedHttpException('Unauthorized user');
}


}
